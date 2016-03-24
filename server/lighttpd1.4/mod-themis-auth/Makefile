LIGHTTPD_DEFS = -DHAVE_CONFIG_H -DHAVE_VERSION_H \
    -DLIBRARY_DIR=\"/usr/lib/lighttpd\" \
    -DSBIN_DIR=\"/usr/sbin\" \
    -D_REENTRANT -D__EXTENSIONS__ -DPIC \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES \
    -DSECURE_COMPARATOR_ENABLED

CFLAGS = $(LIGHTTPD_DEFS) $(COMPAT_DEFS) \
    -I$(LIGHTTPD_DIR) -I$(LIGHTTPD_DIR)/src \
    -g -O2 -Wall -W -Wshadow -pedantic -std=gnu99

CC = gcc
LD = gcc

SRCS = mod_themis_auth.c
OBJS = $(SRCS:.c=.o)

.c.o:
	$(CC) $(CFLAGS) -fPIC -shared -c $<

all: mod_themis_auth.so

mod_themis_auth.so: $(OBJS)
	$(LD) $(LDFLAGS) -fPIC -shared -o $@ $(OBJS) -lthemis

clean:
	$(RM) *.o *.so *~