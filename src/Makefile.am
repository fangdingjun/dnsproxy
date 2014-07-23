bin_PROGRAMS = dnsc dnsproxy sqlite3

noinst_LIBRARIES = libldns.a libsqlite.a

libldns_a_SOURCES = \
    ../third-part/ldns-1.6.17/buffer.c\
    ../third-part/ldns-1.6.17/dane.c\
    ../third-part/ldns-1.6.17/dname.c\
    ../third-part/ldns-1.6.17/dnssec.c\
    ../third-part/ldns-1.6.17/dnssec_sign.c\
    ../third-part/ldns-1.6.17/dnssec_verify.c\
    ../third-part/ldns-1.6.17/dnssec_zone.c\
    ../third-part/ldns-1.6.17/duration.c\
    ../third-part/ldns-1.6.17/error.c\
    ../third-part/ldns-1.6.17/higher.c\
    ../third-part/ldns-1.6.17/host2str.c\
    ../third-part/ldns-1.6.17/host2wire.c\
    ../third-part/ldns-1.6.17/keys.c\
    ../third-part/ldns-1.6.17/net.c\
    ../third-part/ldns-1.6.17/packet.c\
    ../third-part/ldns-1.6.17/parse.c\
    ../third-part/ldns-1.6.17/radix.c\
    ../third-part/ldns-1.6.17/rbtree.c\
    ../third-part/ldns-1.6.17/rdata.c\
    ../third-part/ldns-1.6.17/resolver.c\
    ../third-part/ldns-1.6.17/rr.c\
    ../third-part/ldns-1.6.17/rr_functions.c\
    ../third-part/ldns-1.6.17/sha1.c\
    ../third-part/ldns-1.6.17/sha2.c\
    ../third-part/ldns-1.6.17/str2host.c\
    ../third-part/ldns-1.6.17/tsig.c\
    ../third-part/ldns-1.6.17/update.c\
    ../third-part/ldns-1.6.17/util.c\
    ../third-part/ldns-1.6.17/wire2host.c\
    ../third-part/ldns-1.6.17/zone.c\
    ../third-part/ldns-1.6.17/compat/b64_ntop.c\
    ../third-part/ldns-1.6.17/compat/b64_pton.c\
    ../third-part/ldns-1.6.17/compat/calloc.c\
    ../third-part/ldns-1.6.17/compat/ctime_r.c\
    ../third-part/ldns-1.6.17/compat/gmtime_r.c\
    ../third-part/ldns-1.6.17/compat/inet_aton.c\
    ../third-part/ldns-1.6.17/compat/inet_ntop.c\
    ../third-part/ldns-1.6.17/compat/inet_pton.c\
    ../third-part/ldns-1.6.17/compat/isblank.c\
    ../third-part/ldns-1.6.17/compat/localtime_r.c\
    ../third-part/ldns-1.6.17/compat/malloc.c\
    ../third-part/ldns-1.6.17/compat/memmove.c\
    ../third-part/ldns-1.6.17/compat/realloc.c\
    ../third-part/ldns-1.6.17/compat/strlcpy.c\
    ../third-part/ldns-1.6.17/compat/timegm.c

libsqlite_a_SOURCES = \
  ../third-part/sqlite/sqlite3.c \
  ../third-part/sqlite/sqlite3.h

AM_CFLAGS = -Wall 

dnsc_SOURCES = dnsc.c

dnsproxy_SOURCES = dnsproxy.c parse_cfg.c cache.c cache.h

sqlite3_SOURCES  = ../third-part/sqlite/shell.c

if WIN32
AM_CFLAGS += -I../third-part/ldns-1.6.17/win 
else
AM_CFLAGS += -I../third-part/ldns-1.6.17/linux
endif

AM_CFLAGS += -I../third-part/ldns-1.6.17 -I../third-part/sqlite

sqlite3_CFLAGS = $(AM_CFLAGS) -DHAVE_READLINE=1
#libldns_a_CFLAGS = $(AM_CFLAGS) -DHAVE_CONFIG_H

dnsc_LDADD = $(AM_LDFLAGS) libldns.a
dnsproxy_LDADD =  $(AM_LDFLAGS) libldns.a libsqlite.a
sqlite3_LDADD = $(AM_LDFLAGS) libsqlite.a -lreadline


if WIN32
dnsc_LDADD += -lws2_32
dnsproxy_LDADD += -lws2_32
else
dnsproxy_LDADD += -ldl -lpthread
sqlite3_LDADD += -ldl -lpthread
endif
