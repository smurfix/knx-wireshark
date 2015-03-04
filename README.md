# knx-wireshark

This code implements a rudimentary dissector of KNX datagrams for Wireshark.

The code is initially from svn://svn.code.sf.net/p/knxnetipdissect/code;
the authors appear to be Harald Weillechner and Daniel Lechner.

Matthias Urlichs converted the repository to git and updated the core to
work with Wireshark 1.12. (Older versions are not supported.)

License: GPL v3.

TODO: Add a sub-dissector for the actual KNX/EIB payload.
