#ifndef __FIDO_MAC_H
#define __FIDO_MAC_H

#ifdef __cplusplus
extern "C" {
#endif

// general configuration options
#define SERVER_PORT 8889
#define COMM_BUFFER_SZ 65536

// I've made my own #defines for endianness here incase we need to configure them for various platforms
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
// #  pragma message("Detecting byte-ordering UNIX-style")
#  if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#    define __LITTLE_ENDIAN
#  endif
#  if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define __BIG_ENDIAN
#  endif
#endif

#if defined(__WIN32__) || defined (__WINDOWS__) || defined(_WIN32) || defined(OS_WINDOWS) || defined(_MSC_VER)
#  include <Windows.h>
// #  pragma message("Detecting byte-ordering Windows-style")
#  if REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#    define __LITTLE_ENDIAN
#  else
#    define __BIG_ENDIAN
#  endif
#endif

// #ifdef __LITTLE_ENDIAN
// #  define htonll(x) ((htonl((x) & 0xFFFFFFFF) << 32) | (htonl((x) >> 32)))
// #  define ntohll(x) ((ntohl(((x) & 0xFFFFFFFF00000000) >> 32) | (ntohl((x) & 0xFFFFFFFF) << 32))
// #else
// #  define htonll(x) (x)
// #  define ntohll(x) (x)
// #endif

#if !defined(__LITTLE_ENDIAN) && !defined(__BIG_ENDIAN)
#  error "Couldn't detect endianness: __BYTE_ORDER__ not defined"
#endif

/******************************************************************************
 * FIDO AUTHENTICATOR CONTROLLER MODULES
 *
 * In order to add a new FIDO transport, simply create an init function
 * (module_init_func_t) that returns a module structure (transport_module_t)
 * and add your init function to the initList at the top of fidomac.c
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
    // module_init_func_t init;
    void (*shutdown)();
    transport_cmd_func_t u2fCmd;
    transport_cmd_func_t extraCmds[];
} transport_module_t;

/**
 * module_init_func_t - the generic function pointer type for the initialization function used by modules
 */
typedef transport_module_t *(*module_init_func_t)();

/**
 * printHex -- in case anyone wants to borow my debug function?
 */
void printHex(char *msg, const void *bufin, unsigned int len);

// a helper for figuring out how many modules are defined
#define initListSz ((sizeof (initList))/((sizeof (module_init_func_t))))

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
        // request message fields
        // includes mask
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
        // response message formats
        // doesn't include mask field
        // unsigned char resp_l7_data[];
        // unsigned char data[];
        unsigned char l7_data[1];
        struct {
            unsigned short len;
            unsigned char data[];
        } resp_l16;
        struct {
            unsigned long long len;
            unsigned char data[];
        } resp_l64;
    } l;
} ws_msg_t; //__attribute__((packed, aligned(1)))
#define req_l7_mask  l.l7.mask
#define req_l7_data  l.l7.data
#define req_l7_len   len
#define req_l16_mask l.l16.mask
#define req_l16_data l.l16.data
#define req_l16_len  l.l16.len
#define req_l64_mask l.l64.mask
#define req_l64_data l.l64.data
#define req_l64_len  l.l64.len

#define resp_l7_data  l.l7_data
#define resp_l7_len   len
#define resp_l16_data l.resp_l16.data
#define resp_l16_len  l.resp_l16.len
#define resp_l64_data l.resp_l64.data
#define resp_l64_len  l.resp_l64.len

#ifdef __cplusplus
}
#endif

#endif /* __FIDO_MAC_H */