#include <stdio.h>
#include "fidomac.h"

int dummyInit() {
    printf ("Initializing dummy transport module\n");
    return 0;
}

void dummyShutdown() {
    printf ("Shutting down dummy transport module\n");
}

unsigned char *dummyDoCmd(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    printf ("Dummy transport module doing a command\n");
    printHex ("Dummy data", data, len);
    return NULL;
}

unsigned char *dummyDoPing(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    printf ("PING!");
    printHex ("Ping data", data, len);
    *oLen = len;
    return (unsigned char *)data;
}

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