bin_PROGRAMS = dnsc dnsproxy dnsproxy_glib

AM_CFLAGS = -Wall 

dnsc_SOURCES = dnsc.c dns.h dnsutil.c

dnsproxy_SOURCES = dnsproxy.c dns.h dnsutil.c

dnsproxy_glib_SOURCES = dnsproxy_glib.c dnsutil.c dns.h

dnsc_CFLAGS = $(AM_CFLAGS)
dnsproxy_glib_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS) $(AM_CFLAGS)
dnsproxy_glib_LDADD = $(GLIB_LIBS) $(GIO_LIBS)
dnsproxy_CFLAGS =  $(AM_CFLAGS) -DVERSION=\"0.1.1\" 
dnsc_LDADD = $(AM_LDFLAGS)
dnsproxy_LDADD =  $(AM_LDFLAGS)

if WIN32
dnsc_LDADD += -lws2_32
dnsproxy_LDADD += -lws2_32
dnsproxy_glib_LDADD += -lws2_32
dnsproxy_CFLAGS += -DUSE_SELECT
else
dnsproxy_CFLAGS += -DUSE_EPOLL
endif
