#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h> // for socket
#include <netinet/in.h> // for internet headers
#include <arpa/inet.h> // for ntohs, etc
#include <unistd.h> // for fork
#include <sys/errno.h> // for ECONNRESET
#include "fidomac.h"

/******************************************************************************
 * INIT LIST
 *
 * If you are defining your own authenticator transport, add your init function
 * to list below. It will be called and use the transport_module_t that it
 * returns as the interface for sending / receiving packets.
 *****************************************************************************/
// extern module_init_func_t dummyModuleInit;
// extern transport_module_t *dummyModuleInit();
extern transport_module_t *usbModuleInit();

module_init_func_t initList[] = {
    // dummyModuleInit,
    usbModuleInit
};

static unsigned int moduleListSz = 0;
static transport_module_t **moduleList = NULL;

// internal forunction forward declarations
void initModules();
void startServer();
void cmdLoop(int conn);
unsigned char *runCmd(unsigned char *data, unsigned int len, unsigned int *oLen);
int sendTransportResponse(int conn, unsigned char *m, unsigned char *data, unsigned int len);
// TODO: shutdownModules(): call shutdown functions and free moduleList and moduleList ptrs
static unsigned char *commBuffer = NULL;

// websocket forward declarations
int doWsHandshake(int conn);
unsigned char *parseWsKey(const unsigned char *msg, unsigned int msgLen, unsigned int *oLen);
unsigned char *calcSecKey(unsigned char *key, unsigned int keyLen, unsigned int *oLen);
unsigned char *receiveWsMessage(int conn, int *oLen);
void wsDecodeData (unsigned char *data, int len, unsigned char *mask);
int sendWsResponse(int conn, unsigned char *data, unsigned long long len);

// debugging tools forward declarations
void printHex(char *msg, const void *bufin, unsigned int len);
char *transportTypeToName (int type);

// SHA-1 forward declarations
#define uchar unsigned char
#define uint unsigned int
#define ROTLEFT(a,b) ((a << b) | (a >> (32-b)))
typedef struct {
   uchar data[64];
   uint datalen;
   uint bitlen[2];
   uint state[5];
   uint k[4];
} SHA1_CTX;
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - c) ++b; a += c;
void sha1_transform(SHA1_CTX *ctx, uchar data[]);
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, uchar data[], uint len);
void sha1_final(SHA1_CTX *ctx, uchar hash[]);

// base64 forward declarations
static const unsigned char base64_table[65] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char * base64_encode(const unsigned char *src, size_t len,
         size_t *out_len);

/**
 * main
 *
 * Start here...
 *
 * This intializes the modules and fires up the server that will
 * listen for incoming connections. As new connections are found
 * they will run cmdLoop(), which does the WebSocket handshake
 * then receives authenticator commands and sends responses
 */
int main() {
    printf ("WebSocket server running...\n");

    // TODO: parse command line
    initModules();
    if (moduleListSz < 1) {
        printf ("No transport modules loaded. Maybe try plugging in a device?\n");
        exit (0);
    }
    startServer();
    // TODO: background as daemon
}

/**
 * initModules
 *
 * Calls init() function on each module
 */
void initModules() {
    printf ("Initializing %lu Modules...\n", initListSz);
    transport_module_t *mod;
    int i, type;

    // create the module list
    // this might end up being a few bytes too big, but... oh well :)
    moduleList = malloc (initListSz * sizeof (transport_module_t *));
    if (!moduleList) {
        perror ("Couldn't allocate module list");
        exit(-1);
    }

    for (i = 0; i < initListSz; i++) {
        mod = initList[i](); // call the init function
        if (!mod) {
            printf ("MODULE %d FAILED TO LOAD\n", i);
            continue;
        } else {
            printf ("%s (%s) is loaded.\n", transportTypeToName(mod->type), mod->name);
        }

        // add module to module list
        moduleList[moduleListSz++] = mod;
        // printf ("Loading %s (%d) driver: %s...\n", transportTypeToName(mod->type), mod->type, mod->name);
        // fflush (stdout);
    }
}

/**
 * startServer
 *
 * Listens to the SERVER_PORT for incoming connections and
 * forks off a new child process for each accepted connection.
 * Child processes will run cmdLoop()
 */
void startServer() {
    printf ("Starting up...\n");

    // setup server socket
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf ("Error opening socket: %d\n", s);
        exit (-1);
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(SERVER_PORT);
    int ret = bind (s, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (ret < 0) {
        perror ("Error binding socket");
        exit (-1);
    }
    ret = listen(s, 10);
    if (ret < 0) {
        perror ("Error listening to socket");
        exit (-1);
    }

    // listen for incoming connections forever
    struct sockaddr_in connAddr;
    int conn, connAddrLen, pid;
    while(1) {
        connAddrLen = sizeof(connAddr);
        conn = accept(s, (struct sockaddr *) &connAddr, (socklen_t *)&connAddrLen);
        if (conn < 0) {
            perror ("Error on accept");
            //exit (-1);
            continue;
        }

        // create a child process to manage communications
        pid = fork();
        if (pid < 0) {
            perror("ERROR on fork");
            //exit(-1);
            continue;
        }

        if (pid == 0) { // child process can close the server connection and do its work
            close (s);
            cmdLoop(conn);
            exit (-1);
        } else { // parent process doesn't need the incoming connection anymore
            close (conn);
        }
    }
}

/**
 * cmdLoop
 *
 * Each new client connection runs this function.
 * Basically it does the WebSocket handshake, and then
 * drops into a forever while(1) loop to receive WebSocket
 * messages. Eache WebSocket message is decoded and then
 * passed to the FIDO transport message handling, where
 * the message will be passed to the appropriate authenticator
 */
void cmdLoop(int conn) {
    // do WebSocket handshake
    if (doWsHandshake (conn) < 0) {
        printf ("WebSocket handshake failed\n");
        exit(-1);
    }
    printf ("WebSocket handshake done.\n");

    // forever process incoming messages
    int msgLen;
    unsigned int respLen;
    unsigned char *msg, *resp;
    while (1) {
        // get a WebSocket message...
        printf ("Waiting for message...\n");
        msg = receiveWsMessage(conn, &msgLen);
        if (msg == NULL && msgLen < 0) {
            printf ("Error receiving WebSocket message\n");
            exit (-1);
        }
        if (msgLen == 0) {
            printf ("Non-fatal error receiving WebSocket message\n");
            continue;
        }
        printHex ("Got message", msg, msgLen);

        // ...run the command in the message...
        resp = runCmd (msg, msgLen, &respLen);

        // ...send the response.
        sendTransportResponse (conn, msg, resp, respLen);
    }
}

/**
 * runCmd
 *
 * Parses the transport message and figures out which command
 * to call on which authenticator
 */
unsigned char *runCmd(unsigned char *data, unsigned int len, unsigned int *oLen) {
    transport_msg_t *msg = (transport_msg_t *)data;
    transport_module_t *mod;
    transport_cmd_func_t cmd = NULL;
    unsigned short l = ntohs (msg->len);

    // validate header
    if (msg->magic[0] != 0xF1 | msg->magic[1] != 0xD0) {
        printf ("Bad magic number in header: should have been 0xF1D0\n");
        return NULL;
    }
    if (msg->transport > 3 && msg->transport < 0xFF) {
        printf ("Bad transport: %d\n", msg->transport);
        return NULL;
    }
    // TODO validate len against input length minus the size of the header

    // invoke command on authenticator
    int i;
    unsigned char *ret;
    for (i = 0; i < moduleListSz; i++) {
        mod = moduleList[i];

        // if this message is for a different type of transport, skip this module
        if (mod->type != msg->transport) continue;

        // pick which kind of command it is
        if (msg->cmd == 0) {
            cmd = mod->u2fCmd;
        } else {
            cmd = mod->transportCmd;
        }

        // if we found a command, call it and return the value
        if (cmd != NULL) {
            return cmd(msg->payload, l, oLen);
        }
    }

    // only happens if no suitable module is found
    *oLen = TRANSPORT_RESPONSE_NO_AUTHNR_FOUND;
    return NULL;
}

/**
 * sendTransportResponse
 *
 * Forms a transport response message, and then sends it via sendWsResponse()
 */
int sendTransportResponse(int conn, unsigned char *m, unsigned char *data, unsigned int len) {
    transport_msg_t *msg = (transport_msg_t *)m;
    unsigned int l, respLen;
    if (data != NULL) l = len;
    else l = 0;
    respLen = sizeof (transport_response_t) + l;
    transport_response_t *resp = malloc (respLen);
    if (resp == NULL) {
        printf ("error allocating response");
        return -1;
    }
    resp->magic[0] = 0xF1;
    resp->magic[1] = 0xD0;
    resp->transport = msg->transport;
    resp->cmd = msg->cmd;
    if (data != NULL) {
        memcpy (resp->payload, data, l);
        resp->status = TRANSPORT_RESPONSE_SUCCESS;
        resp->len = l;
    } else { // return an error status
        resp->status = len;
        resp->len = 0;
    }

    int ret;
    ret = sendWsResponse (conn, (unsigned char *)resp, (unsigned long long)respLen);
    free (resp);

    return ret;
}

/******************************************************************************
* A Very Simple WebSocket Server
*
* There are libraries out there to do this sort of thing, such as:
* https://libwebsockets.org
*
* But for the sake of a quick and easy proof of concept that doesn't
* require figuring out cross-platform compilations, here's a dumb
* WebSocket server. This isn't nearly as robust as those other libaries
* but this is all just straight ANSI / POSIX that will build anywhere
* without figuring out build systems, configurations, platforms, etc.
*
* We can always upgrade this later...
******************************************************************************/

/**
 * doWsHandshake
 *
 * Does the WebSocket connection handshake
 * XXX: this probably doesn't perform well with severely malformated messages
 */
int doWsHandshake(int conn) {
    // an arbitrarily large buffer for getting WebSocket client handshake messages
    if (commBuffer == NULL) {
        commBuffer = malloc (COMM_BUFFER_SZ);
    }

    if (commBuffer == NULL) {
        perror ("Couldn't allocate buffer");
        return -1;
    }

    // wait for the handshake message...
    int l;
    // l = recv (conn, commBuffer, COMM_BUFFER_SZ, 0);
    l = read (conn, commBuffer, COMM_BUFFER_SZ);
    if (l == -ECONNRESET) {
        printf ("Connection closed\n");
        exit(0);
    }
    if (l < 0) {
        perror ("Error receiving message");
        return -1;
    }
    printf ("Read %d bytes\n", l);
    commBuffer[l] = 0;
    printf ("Client WebSocket handshake message:\n\"%s\"\n", commBuffer);

    // parse out the clients's security key
    unsigned int keyLen, serverKeyLen;
    unsigned char *key, *serverKey;
    key = parseWsKey (commBuffer, COMM_BUFFER_SZ, &keyLen);
    if (key == NULL) {
        printf ("Couldn't parse WebSocket security key from client\n");
        return -1;
    }
    printf ("Key len: %d\n", keyLen);
    printf ("key: %.24s\n", key);

    // create the server's security key for the response
    serverKey = calcSecKey (key, keyLen, &serverKeyLen);
    printf ("server key len: %d\n", serverKeyLen);
    printf ("server key: \"%s\"\n", serverKey);

    // create and send server message
    // char *serverMsg = "HTTP/1.1 101 Web Socket Protocol Handshake\n" \

    char *serverMsg = "HTTP/1.1 101 Switching Protocols\r\n" \
                      "Upgrade: websocket\r\n" \
                      "Access-Control-Allow-Origin: http://localhost:8888\r\n" \
                      "Sec-WebSocket-Accept: %s\r\n" \
                      "Connection: Upgrade\r\n\r\n";
    printf ("Sending Message:");

    l = snprintf ((char *)commBuffer, COMM_BUFFER_SZ, serverMsg, serverKey);
    if (l < 0 || l > COMM_BUFFER_SZ) {
        printf ("Failed to form WebSocket handshake response\n");
        return -1;
    }
    printf ("Server message:\n\"%s\"\n", commBuffer);
    int ret;
    ret = send (conn, commBuffer, l, 0);
    if (ret < 0) {
        perror ("Sending WebSocket response");
        return -1;
    }
    free (serverKey);

    return 0;
}

/**
 * parseWsKey
 *
 * Parses the "Sec-WebSocket-Key:" header out of the WebSocket handshake message
 * XXX: again, probably not the most robust parsing here...
 */
unsigned char *parseWsKey(const unsigned char *msg, unsigned int msgLen, unsigned int *oLen) {
    char *hdr = "Sec-WebSocket-Key: ";
    unsigned char *ret = NULL;
    int len = strlen (hdr);
    int i;

    // find hdr in msg
    for (i = 0; i < msgLen; i++) {
        if (msg[i] != '\n') continue;
        i++;

        if ((msg[i] == '\n') || // "\n\n" signifies end of message
            ((i+len) >= msgLen)) // not enough message left to contain a key
            break;

        // found the right header, extract the key and length
        if (!strncmp ((char *)&msg[i], hdr, len)) {
            printf ("MATCH FOUND!: %.40s\n", &msg[i]);
            ret = (unsigned char *)&msg[i + len];
            int j;
            for (j = 0; j < (msgLen - i); j++) {
                if (ret[j] == '\n') break;
            }
            *oLen = --j;
            break;
        // } else {
            // printf ("no match at: %.20s\n", &msg[i]);
        }
    }
    return ret;
}

/**
 * calcSecKey
 *
 * Calculated the WebSocket security key returned by the server
 * which is a combination of the key sent by the client and a
 * magic number, SHA-1 hashed, and then returned in base64 format
 */
unsigned char *calcSecKey(unsigned char *key, unsigned int keyLen, unsigned int *oLen) {
    // known good values, for future debugging
    // borrowed from https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    // const char *k = "dGhlIHNhbXBsZSBub25jZQ==";
    // const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    // const char *output = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    // create a string that is a concatenation of key + magic string
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    int magicLen = strlen (magic);
    printf ("keyLen: %d\n", keyLen);
    printf ("magicLen: %d\n", magicLen);

    char buf[keyLen + magicLen];
    printf ("buf size: %lu\n", sizeof(buf));
    memcpy (buf, key, keyLen);
    printHex ("copied key", buf, sizeof(buf));
    memcpy (&buf[keyLen], magic, magicLen);
    printHex ("copied magic", buf, sizeof(buf));
    // printHex ("expect key+magic", km, strlen(km));

    // calculate the SHA1 hash of the key + magic string
    unsigned char hash[20];
    SHA1_CTX ctx;
    sha1_init (&ctx);
    sha1_update (&ctx, (unsigned char *)buf, sizeof (buf));
    sha1_final (&ctx, hash);
    printHex ("calculated hash", hash, sizeof(hash));

    // base64 encode the hash
    unsigned char *ret;
    ret = base64_encode (hash, sizeof(hash), (size_t *)oLen);

    return ret;
}

/**
 * receiveWsMessage
 *
 * reads a WebSocket message from a socket, verifies it, decodes it, and passes the data back
 */
unsigned char *receiveWsMessage(int conn, int *oLen) {
    // create an arbitrarily large buffer for communications
    if (commBuffer == NULL) {
        commBuffer = malloc (COMM_BUFFER_SZ);
    }

    if (commBuffer == NULL) {
        perror ("Couldn't allocate buffer");
        *oLen = -1;
        return NULL;
    }

    // pull a message from a socket
    int l;
    l = read (conn, commBuffer, COMM_BUFFER_SZ);
    if (l == -ECONNRESET) {
        printf ("Connection closed\n");
        exit(0);
    }
    if (l < 0) {
        perror ("Error receiving message");
        *oLen = -1;
        return NULL;
    }
    if (l == 0) {
        printf ("Connection closed\n");
        *oLen = -1;
        return NULL;
    }
    printf ("Received %d bytes.\n", l);

    ws_msg_t *ws = (ws_msg_t *) commBuffer;
    unsigned char *data;
    unsigned long long len;
    unsigned char *mask;
    printf ("Op: %d\n", ws->op);
    printf ("Len: %d\n", ws->len);

    // TODO: someday handle continuations
    if (ws->fin != 1) {
        printf ("WebSocket continuation packets not supported.\n");
        *oLen = 0;
        return NULL;
    }

    // TODO: someday handle ping/pong, etc.
    // 1 = text data, 2 = binary data, 8 = close
    // TODO could probably add some #defines to make these more clear
    if (ws->op != 1 && ws->op != 2 && ws->op != 8) {
        printf ("Only WebSocket text and binary messages are supported\n");
        *oLen = 0;
        return NULL;
    }

    // parse the message length
    if (ws->len < 126) {
        len = ws->len;
        mask = ws->req_l7_mask;
        data = ws->req_l7_data;
    } else if (ws->len == 126) {
        len = ntohs(ws->req_l16_len);
        mask = ws->req_l16_mask;
        data = ws->req_l16_data;
    } else if (ws->len == 127) {
        len = ntohll (ws->req_l64_len);
        mask = ws->req_l64_mask;
        data = ws->req_l64_data;
    } else {
        printf ("unknown length: %d\n", ws->len);
        *oLen = 0;
        return NULL;
    }
    printf ("Payload len: %llu\n", len);
    printHex ("Mask", mask, 4);
    printHex ("Payload", data, len);

    // apply the XOR mask to all the data to unscramble it
    wsDecodeData (data, len, mask);

    // close operation
    if (ws->op == 8) {
        printHex ("Got Close Request", data, len);
        close (conn);
        exit(0);
    }

    *oLen = len;
    return data;
}

/**
 * wsDecodeData
 *
 * Applies (XORs) the WebSocket mask that was received in the header to
 * all of the data.
 */
void wsDecodeData (unsigned char *data, int len, unsigned char *mask) {
    int i;
    //printHex ("data before decode", data, len);
    for (i = 0; i < len; i++) {
        data[i] ^= mask[i%4];
    }
    printHex ("data after decode", data, len);
}

/**
 * sendWsResponse
 *
 * forms the WebSocket response header and then sends that data
 * via the provided socket
 */
int sendWsResponse(int conn, unsigned char *data, unsigned long long len) {
    if (data == NULL) return -1;
    printHex ("sending ws response", data, len);

    unsigned int headerSz; // size of the WebSocket header
    unsigned char simpleLen;
    if (len > 0xFFFF) {
        simpleLen = 127;
        headerSz = 8;
    } else if (len > 125) {
        simpleLen = 126;
        headerSz = 4;
    } else {
        simpleLen = len;
        headerSz = 2;
    }
    unsigned int wsLen = len + headerSz;
    printf ("%llu + %d = wsLen: %d\n", len, headerSz, wsLen);
    ws_msg_t *msg = malloc (wsLen);
    if (msg == NULL) {
        printf ("error allocating ws msg");
        return -1;
    }
    msg->fin = 1;
    msg->op = 2; // TODO: should be #define or enum
    msg->mask = 0;
    msg->len = simpleLen;
    if (simpleLen == 126) {
        // TODO
        printf ("!!! not implemented\n");
    } else if (simpleLen == 127) {
        // TODO
        printf ("!!! not implemented\n");
    } else {
        // BAD! BAD NETWORK PROGRAMMER! NO COPIES!
        // where's a mbuf when you need one...?
        printHex ("data", data, len);
        memcpy (msg->resp_l7_data, data, len);
        len += 2;
    }

    printHex ("ws response msg", (unsigned char *)msg, wsLen);
    int ret;

    // unsigned char testMsg[] = {0x82, 0x04, 0x74, 0x65, 0x73, 0x74};
    // printHex ("SENDING TEST MESSAGE", testMsg, sizeof (testMsg));
    // printf ("Test message is %lu bytes\n", sizeof (testMsg));
    // ret = write (conn, testMsg, sizeof (testMsg));
    ret = write (conn, msg, len);
    printf ("Wrote %d bytes\n", ret);
    if (ret < 0) {
        perror ("Sending WebSocket response");
        return -1;
    }

    return 0;
}

// debugging stuff
void printHex(char *msg, const void *bufin, unsigned int len) {
     const unsigned char *buf = bufin;
     int i;
     printf ("%s\n", msg);
     for (i = 0; i < len; i++) {
         printf ("%.2X ", buf[i] & 0xFF);
         if (i && !((i+1)%16)) printf ("\n");
     }
     if (i%16) printf ("\n");
}

char *transportTypeToName (int type) {
    switch (type) {
        case TRANSPORT_USB: return "usb";
        case TRANSPORT_NFC: return "nfc";
        case TRANSPORT_BLE: return "ble";
        default: return "unknown";
    }
}

// XXX little endian only?

// Code by: B-Con (http://b-con.us)
// Released under the GNU GPL
// MD5 Hash Digest implementation (little endian byte order)

// DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it

void sha1_transform(SHA1_CTX *ctx, uchar data[])
{
   uint a,b,c,d,e,i,j,t,m[80];

   for (i=0,j=0; i < 16; ++i, j += 4)
      m[i] = (data[j] << 24) + (data[j+1] << 16) + (data[j+2] << 8) + (data[j+3]);
   for ( ; i < 80; ++i) {
      m[i] = (m[i-3] ^ m[i-8] ^ m[i-14] ^ m[i-16]);
      m[i] = (m[i] << 1) | (m[i] >> 31);
   }

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];

   for (i=0; i < 20; ++i) {
      t = ROTLEFT(a,5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
      e = d;
      d = c;
      c = ROTLEFT(b,30);
      b = a;
      a = t;
   }
   for ( ; i < 40; ++i) {
      t = ROTLEFT(a,5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
      e = d;
      d = c;
      c = ROTLEFT(b,30);
      b = a;
      a = t;
   }
   for ( ; i < 60; ++i) {
      t = ROTLEFT(a,5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i];
      e = d;
      d = c;
      c = ROTLEFT(b,30);
      b = a;
      a = t;
   }
   for ( ; i < 80; ++i) {
      t = ROTLEFT(a,5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
      e = d;
      d = c;
      c = ROTLEFT(b,30);
      b = a;
      a = t;
   }

   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
}

void sha1_init(SHA1_CTX *ctx)
{
   ctx->datalen = 0;
   ctx->bitlen[0] = 0;
   ctx->bitlen[1] = 0;
   ctx->state[0] = 0x67452301;
   ctx->state[1] = 0xEFCDAB89;
   ctx->state[2] = 0x98BADCFE;
   ctx->state[3] = 0x10325476;
   ctx->state[4] = 0xc3d2e1f0;
   ctx->k[0] = 0x5a827999;
   ctx->k[1] = 0x6ed9eba1;
   ctx->k[2] = 0x8f1bbcdc;
   ctx->k[3] = 0xca62c1d6;
}

void sha1_update(SHA1_CTX *ctx, uchar data[], uint len)
{
   uint t,i;

   for (i=0; i < len; ++i) {
      ctx->data[ctx->datalen] = data[i];
      ctx->datalen++;
      if (ctx->datalen == 64) {
         sha1_transform(ctx,ctx->data);
         DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],512);
         ctx->datalen = 0;
      }
   }
}

void sha1_final(SHA1_CTX *ctx, uchar hash[])
{
   uint i;

   i = ctx->datalen;

   // Pad whatever data is left in the buffer.
   if (ctx->datalen < 56) {
      ctx->data[i++] = 0x80;
      while (i < 56)
         ctx->data[i++] = 0x00;
   }
   else {
      ctx->data[i++] = 0x80;
      while (i < 64)
         ctx->data[i++] = 0x00;
      sha1_transform(ctx,ctx->data);
      memset(ctx->data,0,56);
   }

   // Append to the padding the total message's length in bits and transform.
   DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],8 * ctx->datalen);
   ctx->data[63] = ctx->bitlen[0];
   ctx->data[62] = ctx->bitlen[0] >> 8;
   ctx->data[61] = ctx->bitlen[0] >> 16;
   ctx->data[60] = ctx->bitlen[0] >> 24;
   ctx->data[59] = ctx->bitlen[1];
   ctx->data[58] = ctx->bitlen[1] >> 8;
   ctx->data[57] = ctx->bitlen[1] >> 16;
   ctx->data[56] = ctx->bitlen[1] >> 24;
   sha1_transform(ctx,ctx->data);

   // Since this implementation uses little endian byte ordering and MD uses big endian,
   // reverse all the bytes when copying the final state to the output hash.
   for (i=0; i < 4; ++i) {
      hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff;
      hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff;
      hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
      hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
      hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
   }
}

/*
* Base64 encoding/decoding (RFC1341)
* Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* See README for more details.
*/

/**
* base64_encode - Base64 encode
* @src: Data to be encoded
* @len: Length of the data to be encoded
* @out_len: Pointer to output length variable, or %NULL if not used
* Returns: Allocated buffer of out_len bytes of encoded data,
* or %NULL on failure
*
* Caller is responsible for freeing the returned buffer. Returned buffer is
* nul terminated to make it easier to use as a C string. The nul terminator is
* not included in out_len.
*/
unsigned char * base64_encode(const unsigned char *src, size_t len,
         size_t *out_len)
{
unsigned char *out, *pos;
const unsigned char *end, *in;
size_t olen;
int line_len;

olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
olen += olen / 72; /* line feeds */
olen++; /* nul termination */
if (olen < len)
  return NULL; /* integer overflow */
out = malloc(olen);
if (out == NULL)
  return NULL;

end = src + len;
in = src;
pos = out;
line_len = 0;
while (end - in >= 3) {
  *pos++ = base64_table[in[0] >> 2];
  *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
  *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
  *pos++ = base64_table[in[2] & 0x3f];
  in += 3;
  line_len += 4;
  if (line_len >= 72) {
   // *pos++ = '\n';
   line_len = 0;
  }
}

if (end - in) {
  *pos++ = base64_table[in[0] >> 2];
  if (end - in == 1) {
   *pos++ = base64_table[(in[0] & 0x03) << 4];
   *pos++ = '=';
  } else {
   *pos++ = base64_table[((in[0] & 0x03) << 4) |
           (in[1] >> 4)];
   *pos++ = base64_table[(in[1] & 0x0f) << 2];
  }
  *pos++ = '=';
  line_len += 4;
}

// if (line_len)
  // *pos++ = '\n';

*pos = '\0';
if (out_len)
  *out_len = pos - out;
return out;
}
