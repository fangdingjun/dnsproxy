bin_PROGRAMS = dnsc dnssrv dnsproxy
AM_CFLAGS = -Wall

dnsc_SOURCES = dnsc.c dnsutil.c dns.h

dnsproxy_SOURCES = dnsproxy.c dns.h dnsutil.c
dnssrv_SOURCES = dnssrv.c 

dnssrv_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS)
dnsproxy_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS)

#dnssrv_LIBS= $(GLIB_LIBS) $(GIO_LIBS)
#dnsproxy_LIBS= $(GLIB_LIBS) $(GIO_LIBS)
dnsproxy_LDADD = $(GLIB_LIBS) $(GIO_LIBS)
dnssrv_LDADD = $(GLIB_LIBS) $(GIO_LIBS)

