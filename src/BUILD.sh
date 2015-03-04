#!/bin/sh -ex

## simple script to build this plugin under Linux
## run with "DEBUG=-g" to build a debug version

DEBUG=${DEBUG:--O2}
if ! pkg-config wireshark glib-2.0; then
    echo "You need to install libwireshark-dev and libglib-2.0-dev."
    exit 1
fi
gcc $DEBUG -DWS_MSVC_NORETURN= -DHAVE_STDARG_H $(pkg-config glib-2.0 wireshark --cflags) -c -fPIC  packet-knxnetip.c
ld $DEBUG -shared -o knxnetip.so packet-knxnetip.o $(pkg-config glib-2.0 wireshark --libs)
sudo mv knxnetip.so /usr/lib/$(gcc -print-multiarch)/wireshark/plugins/$(pkg-config wireshark --modversion)
