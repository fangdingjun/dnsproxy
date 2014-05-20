#ifndef DNSPROXY_H
#define DNSPROXY_H

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

#ifdef USE_EPOLL                /* epoll */
#include <sys/epoll.h>
#elif defined USE_SELECT        /* select */
#ifndef WIN32
#include <sys/select.h>
#endif
#else
# error "undefined IO model, please define USE_SELECT or USE_EPOLL macro!!!"
#endif

#include <time.h>

enum arg_t{
    ARG_INT,
    ARG_STRING,
    ARG_STR_ARRARY
};

struct arg_map{
    char *name;
    enum arg_t type;
    void **addr;
};

int get_blackip(char *filename, char **ips);

char *skip_space_at_begin(char *p);
char *skip_space_at_end(char *p);
int parse_cfg(char *filename, struct arg_map *args);


struct msg_data {
    int listen_fd;              /* the socket fd to listen */
    struct sockaddr_in client_addr; /* client socket address */
    char msg_buf[512];          /* message buffer from client */
    int msg_len;                /* the message length */
    int status;                 /* status, 0 for unused, 1 for used */
    int srv_fd;                 /* the server socket fd */
    int fd;                     /* listen fd or server fd */
    time_t last_active;         /* the time for request in */
};

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
#endif

int recv_from_client(struct msg_data *d);
int send_to_server(struct msg_data *d);
int recv_from_server(struct msg_data *d);
int send_to_client(struct msg_data *d, char *msg, int msg_len);
int free_timeout_client();

#endif
