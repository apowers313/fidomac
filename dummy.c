/**
 * This is an example / skeleton of an authenticator module
 */

#include <stdio.h>
#include "fidomac.h"

int dummyInit() {
    printf ("Initializing dummy transport module\n");
    // DO INIT STUFF HERE
    return 0;
}

void dummyShutdown() {
    printf ("Shutting down dummy transport module\n");
    // DO SHUTDOWN STUFF HERE
}

unsigned char *dummyDoCmd(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    static unsigned char retData[] = {0x1, 0x2, 0x3, 0x4};
    printf ("Dummy transport module doing a command\n");
    // SEND THE DATA / APDU TO THE AUTHENTICATOR HERE
    printHex ("Dummy data", data, len);
    *oLen = 4;
    return retData;
}

unsigned char *dummyDoPing(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    printf ("PING!");
    // RUN WHATEVER SPECIAL COMMAND HERE
    printHex ("Ping data", data, len);
    *oLen = len;
    return (unsigned char *)data;
}

// this gets imported as a module in fidomac.c
transport_module_t dummyModule = {
    "dummy",
    TRANSPORT_USB,
    dummyInit,
    dummyShutdown,
    dummyDoCmd,
    {
        dummyDoPing
    }
};