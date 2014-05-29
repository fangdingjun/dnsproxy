bin_PROGRAMS = dnsc dnsproxy

AM_CFLAGS = -Wall 

dnsc_SOURCES = dnsc.c dns.h dnsutil.c

dnsproxy_SOURCES = dnsproxy.c dns.h dnsutil.c

dnsc_CFLAGS = $(AM_CFLAGS)
dnsproxy_CFLAGS =  $(AM_CFLAGS) -DVERSION=\"0.1.1\"
 
dnsc_LDADD = $(AM_LDFLAGS)
dnsproxy_LDADD =  $(AM_LDFLAGS)

if WIN32
    dnsc_LDADD += -lws2_32
    dnsproxy_LDADD += -lws2_32
    dnsproxy_CFLAGS += -DUSE_SELECT
else
    dnsproxy_CFLAGS += -DUSE_EPOLL
endif
