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
struct U2Fob* device;

/**
 * getDevicePath
 *
 * Finds a device with a 0xF1D0 usage page and returns it's path to be used as the test device
 */
char *getDevicePath() {
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

int dummyInit() {
    printf ("Initializing dummy transport module\n");

    char *devicePath = getDevicePath();
    // printf ("Using device path: %s\n", devicePath);

    // create our USB device
    device = U2Fob_create();
    U2Fob_open(device, devicePath);
    free (devicePath);
    U2Fob_init(device);

    return 0;
}

void dummyShutdown() {
    printf ("Shutting down dummy transport module\n");
    U2Fob_destroy(device);
}

unsigned char *usbDoCmd(char *data, unsigned int len, unsigned int *oLen) {
    printf ("Dummy transport module doing a command\n");

    // check arguments
    if (data == NULL || len < 5) {
        printf ("Bad data in usbDoCmd\n");
        *oLen = -1;
        return NULL;
    }

    // massage data into the format that the U2F USB API expects
    uint8_t CLA, INS, P1, P2;
    CLA = data[0];
    INS = data[1];
    P1 = data[2];
    P2 = data[3];

    string rsp;
    unsigned int apduRet;

    // apduRet = U2Fob_apdu(device, CLA, INS, P1, P2,
    //            string(reinterpret_cast<char*>(&data[4]), (len - 4)),
    //            &rsp);
    // cout << "Sign: " << rsp.size() << " bytes in reply:" << rsp;

    // U2F_REGISTER_REQ regReq;
    // for (size_t i = 0; i < sizeof(regReq.nonce); ++i)
    //     regReq.nonce[i] = rand();
    // for (size_t i = 0; i < sizeof(regReq.appId); ++i)
    //     regReq.appId[i] = rand();
    // apduRet = U2Fob_apdu(device, 0, U2F_INS_REGISTER, U2F_AUTH_ENFORCE, 0,
    //                   string(reinterpret_cast<char*>(&regReq), sizeof(regReq)),
    //                   &rsp);

    char d[3] = {0x00, 0x00, 0x00};
    apduRet = U2Fob_apdu(device, 0, 3, 0, 0,
                      string(d),
                      &rsp);

    printf ("U2Fob_apdu returned: 0x%X\n", apduRet);
    unsigned long blah = rsp.size();
    printf ("Response is %lu bytes\n", blah);
    *oLen = blah;
    unsigned char *ret = (unsigned char *)malloc(blah);
    memcpy (ret, rsp.c_str(), blah);
    return ret;

    // return NULL;
}

unsigned char *dummyDoPing(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    printf ("PING!");
    // RUN WHATEVER SPECIAL COMMAND HERE
    // printHex ((char *)"Ping data", data, len);
    *oLen = len;
    return (unsigned char *)data;
}

// this gets imported as a module in fidomac.c
// transport_module_t dummyModule = {
//     (char *)"dummy",
//     TRANSPORT_USB,
//     dummyInit,
//     dummyShutdown,
//     usbDoCmd,
//     // {
//     //     dummyDoPing
//     // }
// };

// debugging stuff
void printHex(char *msg, const void *bufin, unsigned int len) {
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
    // 000103000000400AD6F04AC74397B448E25B62EB5210FF0585CD7C0F56AA2033D07A20AEA80955CD63A077A3366AED8BA29D261D34AE41FCEBA8D41ED13319AE65477264B4F4020000
    unsigned int len = sizeof (data);
    char *ret;
    ret = (char *)usbDoCmd (data, len, &len);
    printHex ((char *)"response",ret, len);

    dummyShutdown();
}
