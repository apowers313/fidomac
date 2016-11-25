# Generic configuration
CP=cp
LDFLAGS=-Llibu2ftest/HID -lu2ftest
CFLAGS=-I. -Ilibu2ftest/HID -Ilibu2ftest/HID/hidapi/hidapi
LIBU2FTEST=libu2ftest/HID/libu2ftest.a

# Platform specific configuration
UNAME := $(shell uname)

# Linux
ifeq ($(UNAME), Linux)
CFLAGS+=-Ihidapi/hidapi -D__OS_LINUX -Icore/include
LDFLAGS+=-lrt -ludev
endif  # Linux

# OSX
ifeq ($(UNAME), Darwin)
CFLAGS+=-Ihidapi/hidapi -Icore/include -D__OS_MAC
LDFLAGS+=-framework IOKit -framework CoreFoundation
endif  # Darwin

all: fidomac

clean:
	rm -rf fidomac libu2ftest

libu2ftest:
	git clone https://github.com/apowers313/libu2ftest.git

$(LIBU2FTEST): libu2ftest libu2ftest/HID/u2f_util.cc libu2ftest/HID/*.h libu2ftest/HID/Makefile
	$(MAKE) -C libu2ftest/HID

fidomac: fidomac.c fidomac.h dummy.c $(LIBU2FTEST)
	gcc fidomac.c dummy.c -I. -o $@ $(LDFLAGS)

test: usb.cc $(LIBU2FTEST)
	g++ $(CFLAGS) -o $@ usb.cc $(LDFLAGS)