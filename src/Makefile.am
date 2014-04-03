bin_PROGRAMS = dnsc dnssrv dnsproxy
AM_CFLAGS = -Wall
dnsc_SOURCES = dnsc.c dnsutil.c dns.h
dnsproxy_SOURCES = dnsproxy.c dns.h dnsutil.c
dnssrv_SOURCES = dnssrv.c 
dnssrv_CFLAGS = $(shell pkg-config --cflags glib-2.0 gio-2.0)
dnsproxy_CFLAGS = $(shell pkg-config --cflags glib-2.0 gio-2.0)
dnssrv_LDFLAGS = $(shell pkg-config --libs glib-2.0 gio-2.0)
dnsproxy_LDFLAGS = $(shell pkg-config --libs glib-2.0 gio-2.0)

