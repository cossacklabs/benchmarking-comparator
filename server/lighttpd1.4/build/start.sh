#/bin/bash

LD_LIBRARY_PATH=. ./lighttpd -m ./libs -f ./config/lighttpd.conf -D 2>$1