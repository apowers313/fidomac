#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h> // for socket
#include <netinet/in.h> // for internet headers
#include <arpa/inet.h> // for ntohs, etc
#include <unistd.h> // for fork
#include "fidomac.h"

/******************************************************************************
 * MODULE LIST
 *
 * If you are defining your own authenticator transport, build your
 * transport_module_t elsewhere and then add it to the list here.
 *****************************************************************************/
extern transport_module_t dummyModule;

transport_module_t *moduleList[] = {
    &dummyModule
};

// internal forunction forward declarations
void initModules();
void startServer();
void cmdLoop(int conn);
unsigned char *runCmd(unsigned char *data, unsigned int len, unsigned int *oLen);
int sendTransportResponse(unsigned char *m, unsigned char *data, unsigned int len);

// websocket forward declarations
void doWsHandshake();
unsigned char *parseWsKey(const unsigned char *msg, unsigned int msgLen, unsigned int *oLen);
unsigned char *calcSecKey(unsigned char *key, unsigned int keyLen, unsigned int *oLen);
void wsDecodeData (unsigned char *data, int len, unsigned char *mask);
int sendWsResponse(unsigned char *data, unsigned long long len);

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
    startServer();
}

/**
 * initModules
 *
 * Calls init() function on each module
 */
void initModules() {
    printf ("Loading %lu Modules...\n", moduleListSz);
    transport_module_t *mod;
    int i, type;
    for (i = 0; i < moduleListSz; i++) {
        mod = moduleList[i];
        printf ("Loading %s (%d) driver: %s...\n", transportTypeToName(mod->type), mod->type, mod->name);
        fflush (stdout);
        if (mod->init()) {
            // TODO: if this fails, it should be removed for the list or something
            printf ("FAILED TO LOAD: (%s): %s\n", transportTypeToName(mod->type), mod->name);
        } else {
            printf ("%s (%s) is loaded.\n", transportTypeToName(mod->type), mod->name);
        }
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
    // create an arbitrarily large buffer for communications
    unsigned char *buf = malloc (BUFFER_SZ);
    if (buf == NULL) {
        perror ("Couldn't allocate buffer");
        exit(-1);
    }

    // forever process incoming messages
    int l;
    while (1) {
        l = recv (conn, buf, BUFFER_SZ, 0);
        if (l < 0) {
            perror ("Error receiving message");
            continue;
        }
        printf ("Received %d bytes.\n", l);
    }

    // TODO: refactor into wsRecieveData() or something
    //unsigned char testMsg[] = {0x81, 0x84, 0x9D, 0xA4, 0x01, 0x42, 0xE9, 0xC1, 0x72, 0x36};
    unsigned char testMsg[] = {0x81, 0x8A, 0x00, 0x00, 0x00, 0x00, 0xF1, 0xD0, 0x01, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04};
    ws_msg_t *ws = (ws_msg_t *) testMsg;
    unsigned char *data;
    unsigned long long len;
    unsigned char *mask;
    printf ("Op: %d\n", ws->op);
    printf ("Len: %d\n", ws->len);
    // TODO: someday handle continuations
    if (ws->fin != 1) {
        printf ("WebSocket continuation packets not supported.\n");
        return;
    }
    // TODO: someday handle ping/pong, etc.
    if (ws->op != 1 && ws->op != 2) {
        printf ("Only WebSocket text and binary messages are supported\n");
        return;
    }
    if (ws->len < 126) {
        len = ws->len;
        mask = ws->l.l7.mask;
        data = ws->l.l7.data;
    } else if (ws->len == 126) {
        len = ws->l.l16.len; // TODO: ntohs
        mask = ws->l.l16.mask;
        data = ws->l.l16.data;
    } else if (ws->len == 127) {
        len = ws->l.l64.len;
        mask = ws->l.l64.mask;
        data = ws->l.l64.data; // TODO: ntohll
    } else {
        printf ("unknown length: %d\n", ws->len);
        return;
    }
    printf ("Payload len: %llu\n", len);
    printHex ("Mask", mask, 4);
    printHex ("Payload", data, len);
    wsDecodeData (data, len, mask);
    unsigned char *ret;
    unsigned int oLen;
    ret = runCmd (data, len, &oLen);
    sendTransportResponse (data, ret, oLen);
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
        if (mod->type != msg->transport) continue;
        if (msg->cmd == 0) {
            return mod->u2fCmd(msg->payload, l, oLen);
        } else {
            return mod->extraCmds[msg->cmd-1](msg->payload, l, oLen);
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
int sendTransportResponse(unsigned char *m, unsigned char *data, unsigned int len) {
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
    ret = sendWsResponse ((unsigned char *)resp, (unsigned long long)respLen);
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
void doWsHandshake() {
    // TODO: read message from socket
    char *testMsg = "GET /test HTTP/1.1\n" \
                    "Host: localhost:8889\n" \
                    "Connection: Upgrade\n" \
                    "Pragma: no-cache\n" \
                    "Cache-Control: no-cache\n" \
                    "Upgrade: websocket\n" \
                    "Origin: http://localhost:8888" \
                    "Sec-WebSocket-Version: 13" \
                    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36" \
                    "Accept-Encoding: gzip, deflate, sdch, br" \
                    "Accept-Language: en-US,en;q=0.8" \
                    "Cookie: JingoSession=eyJmbGFzaCI6e319; JingoSession.sig=S3n_cgJ6jIpa50AhCKH52aRFo00; current-breadcrumb=%2523%252Badd-subscriber.jsp*\n" \
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\n" \
                    "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\n\n";
//                     "Sec-WebSocket-Key: xe7hanpDJIrpWpf6i8rA8w==\n" \

    unsigned int keyLen, serverKeyLen;
    unsigned char *key, *serverKey;
    key = parseWsKey ((unsigned char *)testMsg, strlen (testMsg), &keyLen);
    printf ("Key len: %d\n", keyLen);
    printf ("key: %.24s\n", key);

    serverKey = calcSecKey (key, keyLen, &serverKeyLen);
    printf ("server key len: %d\n", serverKeyLen);
    printf ("server key: %s\n", serverKey);

    char *serverMsg = "HTTP/1.1 101 Switching Protocols\n" \
                      "Upgrade: websocket\n" \
                      "Connection: Upgrade\n" \
                      "Sec-WebSocket-Accept: %s\n\n";
    printf ("Sending Message:");
    // TODO: write serverMsg to socket
    printf (serverMsg, serverKey);
    free (serverKey);
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
            *oLen = j;
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
    const char *k = "dGhlIHNhbXBsZSBub25jZQ==";
    // const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const char *km = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    printf ("Key len %lu\n", strlen (k));
    printf ("Key: %s\n", k);

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
    printHex ("expect key+magic", km, strlen(km));

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
int sendWsResponse(unsigned char *data, unsigned long long len) {
    if (data == NULL) return -1;
    printHex ("sending ws response", data, len);

    unsigned int adj; // number of bytes smaller than the max length
    unsigned char simpleLen;
    if (len > 0xFFFF) {
        simpleLen = 127;
        adj = 0;
    } else if (len > 125) {
        simpleLen = 126;
        adj = 5;
    } else {
        simpleLen = len;
        adj = 7;
    }
    unsigned int wsLen = len + sizeof (ws_msg_t) - adj;
    printf ("wsLen: %d\n", wsLen);
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
        // YOU LEFT OFF HERE
    }
    msg->mask = 0;

    printHex ("ws response msg", (unsigned char *)msg, wsLen);
    // TODO: write message to socket

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
     if ((i+1)%16) printf ("\n");
}

char *transportTypeToName (int type) {
    switch (type) {
        case TRANSPORT_USB: return "usb";
        case TRANSPORT_NFC: return "nfc";
        case TRANSPORT_BLE: return "ble";
        default: return "unknown";
    }
}

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
   *pos++ = '\n';
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

if (line_len)
  *pos++ = '\n';

*pos = '\0';
if (out_len)
  *out_len = pos - out;
return out;
}
