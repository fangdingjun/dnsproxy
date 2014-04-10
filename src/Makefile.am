bin_PROGRAMS = dnsc dnsproxy
AM_CFLAGS = -Wall

dnsc_SOURCES = dnsc.c dnsutil.c dns.h

dnsproxy_SOURCES = dnsproxy.c dns.h dnsutil.c

dnsproxy_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS)

#dnsproxy_LIBS= $(GLIB_LIBS) $(GIO_LIBS)
dnsproxy_LDADD = $(GLIB_LIBS) $(GIO_LIBS)

