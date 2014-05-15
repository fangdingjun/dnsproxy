bin_PROGRAMS = dnsc dnsproxy dnsproxy_2

AM_CFLAGS = -Wall

#lib_LTLIBRARIES = libdnsutil.la

#libdnsutil_la_SOURCES = dnsutil.c
#libdnsutil_la_CFLAGS = -fPIC
#libdnsutil_la_LDFLAGS= -shared -fPIC

dnsc_SOURCES = dnsc.c dns.h dnsutil.c

dnsproxy_SOURCES = dnsproxy.c dns.h dnsutil.c

dnsproxy_2_SOURCES = dnsproxy_2.c dnsutil.c

dnsproxy_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS) 
#dnsproxy_LIBS= $(GLIB_LIBS) $(GIO_LIBS)
dnsproxy_LDADD = $(GLIB_LIBS) $(GIO_LIBS)
dnsproxy_2_CFLAGS =  
dnsc_LDADD =  
dnsproxy_2_LDADD =

if WIN32
dnsc_LDADD += -lws2_32
dnsproxy_LDADD += -lws2_32
dnsproxy_2_LDADD += -lws2_32
dnsproxy_2_CFLAGS += -DUSE_SELECT
else
dnsproxy_2_CFLAGS += -DUSE_SELECT
endif
