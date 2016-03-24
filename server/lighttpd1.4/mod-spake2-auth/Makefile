LIGHTTPD_DEFS = -DHAVE_CONFIG_H -DHAVE_VERSION_H \
    -DLIBRARY_DIR=\"/usr/lib/lighttpd\" \
    -DSBIN_DIR=\"/usr/sbin\" \
    -D_REENTRANT -D__EXTENSIONS__ -DPIC \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES \
    -DSECURE_COMPARATOR_ENABLED

CFLAGS = $(LIGHTTPD_DEFS) $(COMPAT_DEFS) \
    -I$(LIGHTTPD_DIR) -I$(LIGHTTPD_DIR)/src -I. -I/home/andrey/progs/Hermes/libs/boringssl-build/src/include\
    -g -O2 -Wall -W -Wshadow -pedantic -std=gnu99

CC = gcc
LD = gcc

SRCS = mod_spake2_auth.c curve25519.c spake25519.c
OBJS = $(SRCS:.c=.o)

.c.o:
	$(CC) $(CFLAGS) -fPIC -shared -c $<

all: mod_spake2_auth.so

mod_spake2_auth.so: $(OBJS)
	$(LD) $(LDFLAGS) -fPIC -shared -o $@ $(OBJS) -L. -lboringssl

clean:
	$(RM) *.o *.so *~