#ifndef __FIDO_MAC_H
#define __FIDO_MAC_H

// general configuration options
#define SERVER_PORT 8889
#define BUFFER_SZ 65536

// I've made my own #defines for endianness here incase we need to configure them for various platforms
// XXX TODO: not sure about these macros for MSVC
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN
#endif

/******************************************************************************
 * FIDO AUTHENTICATOR CONTROLLER MODULES
 *
 * In order to add a new FIDO transport, simply define a new transport_module_t
 * and add it to the moduleList in fidomac.c
 *****************************************************************************/

/**
 * transport_cmd_func_t - the generic function pointer type for command functions
 */
typedef unsigned char *(*transport_cmd_func_t)(const unsigned char *data, unsigned int len, unsigned int *oLen);

/**
 * transport_module_t - each authentictor module / transport must supply one of these
 */
typedef struct {
    char *name;
    unsigned char type;
    int (*init)();
    void (*shutdown)();
    transport_cmd_func_t u2fCmd;
    transport_cmd_func_t extraCmds[];
} transport_module_t;

/**
 * printHex -- in case anyone wants to borow my debug function?
 */
void printHex(char *msg, const void *bufin, unsigned int len);

// a helper for figuring out how many modules are defined
#define moduleListSz ((sizeof (moduleList))/((sizeof (transport_module_t *))))

/******************************************************************************
 * FIDO TRANSPORT PROTOCOL
 *
 * This should all be strictly internal and never exposed to authenticators.
 * It's just a lightweight protocol for deciding which commands to call on
 * which authenticators.
 *****************************************************************************/

/**
 * transport_msg_t - a transport request message
 */
typedef struct {
    unsigned char magic[2];
    unsigned char transport;
    unsigned char cmd;
    unsigned short len;
    unsigned char payload[];
} transport_msg_t;
// extra commands, for authenticator-specific behaviors
#define USB_EXTRA_CMD_PING 1

/**
 * transport_response_t - a transport response message
 */
typedef struct {
    unsigned char magic[2];
    unsigned char transport;
    unsigned char cmd;
    unsigned char status;
    unsigned short len;
    unsigned char payload[];
} transport_response_t;
// Response types
#define TRANSPORT_RESPONSE_SUCCESS 0
#define TRANSPORT_RESPONSE_FAILURE 1
#define TRANSPORT_RESPONSE_NO_AUTHNR_FOUND 2

// Transport types
// TODO: turn these #defines into enums
#define TRANSPORT_USB 1
#define TRANSPORT_NFC 2
#define TRANSPORT_BLE 3
#define TRANSPORT_ALL 0xFF

/******************************************************************************
 * WEBSOCKET PROTOCOL
 *
 * As defined by RFC XXXX for WebSockets
 * See also: https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
 *****************************************************************************/

/**
 * ws_msg_t - websock message type
 *
 * Note: I realize there's religion around using bitfields for parsing binary protocols...
 */
#pragma pack(1)
typedef struct {
#ifdef __LITTLE_ENDIAN
    unsigned char op:4,
                  rsv:3,
                  fin:1;
    unsigned char len:7,
                  mask:1;
#else // __BIG_ENDIAN
    unsigned char fin:1,
                  rsv:3,
                  op:4;
    unsigned char mask:1,
                  len:7;
#endif
    union {
        struct {
            unsigned char mask[4];
            unsigned char data[];
        } l7;
        struct {
            unsigned short len;
            unsigned char mask[4];
            unsigned char data[];
        } l16;
        struct {
            unsigned long long len;
            unsigned char mask[4];
            unsigned char data[];
        } l64;
    } l;
} ws_msg_t; // TODO: alignment() rather than pragma pack()?

#endif /* __FIDO_MAC_H */