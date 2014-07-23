/*
#============================================
# Filename:
#    dnsproxy.h
# Author:
#    fangdingjun@gmail.com
# License:
#   GPLv3 (http://www.gnu.org/licenses/gpl-3.0.html)
# Description:
#   header files used by dnsproxy.c
#============================================
*/

#ifndef DNSPROXY_H
#define DNSPROXY_H
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#endif

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <time.h>

enum arg_t {
    ARG_INT,
    ARG_STRING,
    ARG_STR_ARRARY
};

struct arg_map {
    char *name;
    enum arg_t type;
    void **addr;
};

int get_blackip(char *filename, char **ips);

char *skip_space_at_begin(char *p);
char *skip_space_at_end(char *p);
int parse_cfg(char *filename, struct arg_map *args);

#define LOG_DEBUG 4
#define LOG_INFO 3
#define LOG_WARNING 2
#define LOG_ERROR 1
#define LOG_CRITICAL 0

#ifdef WIN32
#define NULLDEV "nul"
#else
#define NULLDEV "/dev/null"
#endif

#define log(level, fmt, args...) do{ \
    if (level > loglevel){ \
        break; \
    } \
    if(logfp){ \
        time_t t=time(NULL);\
        struct tm *t1=localtime(&t);\
        char t2[40];\
        sprintf(t2, "%04d-%02d-%02d %02d:%02d:%02d",\
                t1->tm_year+1900, t1->tm_mon+1, t1->tm_mday,\
                t1->tm_hour,t1->tm_min,t1->tm_sec);\
        fprintf(logfp,"%s: " fmt, t2, ## args); \
        fflush(logfp); \
    } \
} while(0)

#define DBG(fmt, args...) log(LOG_DEBUG,"DEBUG: "  fmt,  ## args)
#define INFO(fmt, args...) log(LOG_INFO,"INFO: "  fmt,  ## args)
#define WARN(fmt, args...) log(LOG_WARNING,"WARN: "  fmt, ## args)
#define ERR(fmt, args...) log(LOG_ERROR,"ERROR: "  fmt,  ## args)

#ifdef WIN32
#define perror(msg) do {\
    char errmsg[1024];\
    int errcode = WSAGetLastError();\
    int len = FormatMessage(\
    FORMAT_MESSAGE_FROM_SYSTEM,\
    0, errcode, 0, errmsg, sizeof(errmsg), 0);\
    if(len){ ERR(msg ": %s", errmsg); } \
    else{ ERR(msg ": unknown error\n");}\
 }while(0)

#define close closesocket
#endif /* end win32 */
#endif /* end DNSPROXY_H */
