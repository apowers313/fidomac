/**
 * This is an example / skeleton of an authenticator module
 */

#include <stdio.h>
#include <stdlib.h>
#include "fidomac.h"

static void dummyShutdown();
static unsigned char *dummyDoCmd(const unsigned char *data, unsigned int len, unsigned int *oLen);
static unsigned char *dummyDoPing(const unsigned char *data, unsigned int len, unsigned int *oLen);


transport_module_t *dummyModuleInit() {
    printf ("Initializing dummy transport module\n");

    // DO INIT STUFF HERE

    transport_module_t *dummyModule = (transport_module_t *)malloc (sizeof (transport_module_t));
    if (!dummyModule) {
        perror ("Error allocating USB module");
        exit (-1);
    }

    dummyModule->name = "dummy";
    dummyModule->type = TRANSPORT_USB;
    // dummyModule->init = usbModuleInit;
    dummyModule->shutdown = dummyShutdown;
    dummyModule->u2fCmd = dummyDoCmd;

    return dummyModule;
}

static unsigned char *dummyDoCmd(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    static unsigned char retData[] = {0x1, 0x2, 0x3, 0x4};
    printf ("Dummy transport module doing a command\n");
    // SEND THE DATA / APDU TO THE AUTHENTICATOR HERE
    printHex ("Dummy data", data, len);
    *oLen = 4;
    return retData;
}

static unsigned char *dummyDoPing(const unsigned char *data, unsigned int len, unsigned int *oLen) {
    printf ("PING!");
    // RUN WHATEVER SPECIAL COMMAND HERE
    printHex ("Ping data", data, len);
    *oLen = len;
    return (unsigned char *)data;
}

static void dummyShutdown() {
    printf ("Shutting down dummy transport module\n");
    // DO SHUTDOWN STUFF HERE
}
