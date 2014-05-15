bin_PROGRAMS = dnsc dnsproxy dnsproxy_glib

AM_CFLAGS = -Wall 

MYFLAGS = -g -O2

#lib_LTLIBRARIES = libdnsutil.la

#libdnsutil_la_SOURCES = dnsutil.c
#libdnsutil_la_CFLAGS = -fPIC
#libdnsutil_la_LDFLAGS= -shared -fPIC

dnsc_SOURCES = dnsc.c dns.h dnsutil.c

dnsproxy_SOURCES = dnsproxy.c dns.h dnsutil.c

dnsproxy_glib_SOURCES = dnsproxy_glib.c dnsutil.c dns.h

dnsproxy_glib_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS) $(AM_CFLAGS) $(MYFLAGS)
dnsproxy_glib_LDADD = $(GLIB_LIBS) $(GIO_LIBS)
dnsproxy_CFLAGS =  $(AM_CFLAGS) -DVERSION=\"0.1.1\" $(MYFLAGS)
dnsc_LDADD = $(LDFLAGS)
dnsproxy_LDADD =  $(LDFLAGS)

if WIN32
#AM_LDFLAGS = -lws2_32
dnsc_LDADD += -lws2_32
dnsproxy_LDADD += -lws2_32
dnsproxy_glib_LDADD += -lws2_32
dnsproxy_CFLAGS += -DUSE_SELECT
else
dnsproxy_CFLAGS += -DUSE_EPOLL
endif
