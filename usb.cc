/**
 * This is an example / skeleton of an authenticator module
 */
#include <stdio.h> // printf
#include <stdlib.h> // malloc
#include <string.h> // strlen
#include <u2f_util.h>
#include "fidomac.h"

// for listing devices
#include "hidapi.h" // hid_init
#ifdef __OS_WIN
#define QUOTE "\""
#else
#define QUOTE ""
#endif

using namespace std;

// globals
static struct U2Fob* device;

// external interfaces
// usbModuleInit returns a transport_module_t that includes function pointers
// to other interfaces
// the main module is C, so we have to define the main interface as a C function so that it links right
extern "C" transport_module_t *usbModuleInit();
static unsigned char *usbDoCmd(const unsigned char *data, unsigned int len, unsigned int *oLen);
static unsigned char *usbDoPing(const unsigned char *data, unsigned int len, unsigned int *oLen);
static void usbShutdown();
// internal helper functions
static char *getDevicePath();

transport_module_t *usbModuleInit() {
    printf ("Initializing USB transport module\n");

    char *devicePath = getDevicePath();
    if (!devicePath) {
        printf ("No USB Devices Found\n");
        return NULL;
    }
    // printf ("Using device path: %s\n", devicePath);

    // create our USB device
    device = U2Fob_create();
    U2Fob_open(device, devicePath);
    free (devicePath);
    U2Fob_init(device);

    // this gets imported as a module in fidomac.c
    transport_module_t *usbModule = (transport_module_t *)malloc (sizeof (transport_module_t));
    if (!usbModule) {
        perror ("Error allocating USB module");
        exit (-1);
    }

    usbModule->name = (char *)"usb";
    usbModule->type = TRANSPORT_USB;
    usbModule->shutdown = usbShutdown;
    usbModule->u2fCmd = usbDoCmd;

    return usbModule;
}

static unsigned char *usbDoCmd(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    printf ("Dummy transport module doing a command\n");

    // check arguments
    if (data == NULL || len < 5) {
        printf ("Bad data in usbDoCmd\n");
        *oLen = -1;
        return NULL;
    }

    string rsp;
    unsigned int apduRet;

    // send the raw message
    apduRet = U2Fob_exchange_apdu_buffer (device, (char *)data, len, &rsp);

    // format return values
    unsigned long sz = rsp.size();
    *oLen = sz + 2;
    unsigned char *ret = (unsigned char *)malloc(sz + 2);
    if (!ret) {
        perror ("Couldn't allocate response");
        exit (-1);
    }
    memcpy (ret, rsp.c_str(), sz);

    // add the status code back to the end of the buffer
    ret[sz] = (apduRet & 0xFF00) >> 8;
    ret[sz+1] = apduRet & 0xFF;

    return ret;
}

static unsigned char *usbDoPing(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    printf ("PING!");
    // RUN WHATEVER SPECIAL COMMAND HERE
    // printHex ((char *)"Ping data", data, len);
    *oLen = len;
    return (unsigned char *)data;
}

static void usbShutdown() {
    printf ("Shutting down USB transport module\n");
    U2Fob_destroy(device);
}

/**
 * getDevicePath
 *
 * Finds a device with a 0xF1D0 usage page and returns it's path to be used as the test device
 */
static char *getDevicePath() {
// Enumerate and print the HID devices on the system
    struct hid_device_info *devs, *cur_dev;
    char *device_path = NULL;
    int len;

    hid_init();
    devs = hid_enumerate(0x0, 0x0);
    cur_dev = devs;
    while (cur_dev) {
        if (cur_dev->usage_page == 0xF1D0 && !device_path) {
            printf("FIDO USB Device Found\n");
            printf("  VID PID:      %04hx %04hx\n",
                cur_dev->vendor_id, cur_dev->product_id);
            printf("  Page/Usage:   0x%x/0x%x (%d/%d)\n",
                cur_dev->usage_page, cur_dev->usage,
                cur_dev->usage_page, cur_dev->usage);
            printf("\n");
            printf("  Manufacturer: %ls\n", cur_dev->manufacturer_string);
            printf("  Product:      %ls\n", cur_dev->product_string);
            printf("  Device path:  %s%s%s\n",
                QUOTE, cur_dev->path, QUOTE);
            printf("\n");

            len = strlen(cur_dev->path) + 1;
            device_path = (char *)malloc (len);
            if (!device_path) {
                perror ("Fatal error: Memory allocation failed while finding USB device");
                exit (-1);
            }
            memcpy (device_path, cur_dev->path, len);
        }

        cur_dev = cur_dev->next;
    }
    hid_free_enumeration(devs);

    hid_exit();

    return (device_path);
}

// debugging stuff
/* void printHex(char *msg, const void *bufin, unsigned int len) {
    if (msg == NULL || bufin == NULL) return;
    const unsigned char *buf = (const unsigned char *)bufin;
    int i;
    printf ("%s\n", msg);
    for (i = 0; i < len; i++) {
        printf ("%.2X ", buf[i] & 0xFF);
        if (i && !((i+1)%16)) printf ("\n");
    }
    if (i%16) printf ("\n");
}

int main() {
    dummyInit();

    // send test message
    // U2F version message
    char data[] = {0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
    // enroll message
    // char data[] = {
    //     0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x40, 0x0A,
    //     0xD6, 0xF0, 0x4A, 0xC7, 0x43, 0x97, 0xB4, 0x48,
    //     0xE2, 0x5B, 0x62, 0xEB, 0x52, 0x10, 0xFF, 0x05,
    //     0x85, 0xCD, 0x7C, 0x0F, 0x56, 0xAA, 0x20, 0x33,
    //     0xD0, 0x7A, 0x20, 0xAE, 0xA8, 0x09, 0x55, 0xCD,
    //     0x63, 0xA0, 0x77, 0xA3, 0x36, 0x6A, 0xED, 0x8B,
    //     0xA2, 0x9D, 0x26, 0x1D, 0x34, 0xAE, 0x41, 0xFC,
    //     0xEB, 0xA8, 0xD4, 0x1E, 0xD1, 0x33, 0x19, 0xAE,
    //     0x65, 0x47, 0x72, 0x64, 0xB4, 0xF4, 0x02, 0x00,
    //     0x00};
    unsigned int len = sizeof (data);
    char *ret;
    ret = (char *)usbDoCmd (data, len, &len);
    printHex ((char *)"response",ret, len);

    dummyShutdown();
} */
