
//#define USE_SELECT
//#define DEBUG
//#define VERSION "0.1"
#include <stdio.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
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
# error "unsupported methed"
#endif

#include <time.h>
#include "dns.h"

#define MAX_QUEUE 100

#ifdef WIN32
#define perror(msg) do {\
    char *errstr = NULL;\
    int errcode = WSAGetLastError();\
    int len = FormatMessage(\
    FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,\
    0, errcode, 0, (char *)&errstr,0,0);\
    if(len){ printf(msg ": %.*s", len, errstr); } \
    else{ printf(msg ": unknown error\n");}\
    LocalFree(errstr);\
 }while(0)
#define close closesocket
#endif

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

char *listen_ip = "127.0.0.1";

int listen_port = 53;

char *servers[] = {
    "8.8.8.8",
    "114.114.114.114",
    "208.67.222.222",
    "1.2.4.8",
    NULL
};

/* the ip lists that china GFW used for DNS cache pollution 
*  http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93
*/
char *blacklist =
    "1.1.1.1,255.255.255.255,74.125.127.102,74.125.155.102,74.125.39.102,74.125.39.113,209.85.229.138,4.36.66.178,8.7.198.45,37.61.54.158,46.82.174.68,59.24.3.173,64.33.88.161,64.33.99.47,64.66.163.251,65.104.202.252,65.160.219.113,66.45.252.237,72.14.205.104,72.14.205.99,78.16.49.15,93.46.8.89,128.121.126.139,159.106.121.75,169.132.13.103,192.67.198.6,202.106.1.2,202.181.7.85,203.161.230.171,203.98.7.65,207.12.88.98,208.56.31.43,209.145.54.50,209.220.30.174,209.36.73.33,209.85.229.138,211.94.66.147,213.169.251.35,216.221.188.182,216.234.179.13,243.185.187.3,243.185.187.39";

#ifdef USE_EPOLL
int epfd;
struct epoll_event events[MAX_QUEUE + 1];
#endif

struct msg_data msg[MAX_QUEUE + 1];

int recv_from_client(struct msg_data *d);
int send_to_server(struct msg_data *d);
int recv_from_server(struct msg_data *d);
int send_to_client(struct msg_data *d, char *msg, int msg_len);
int free_timeout_client();

int recv_from_client(struct msg_data *d)
{
    socklen_t l;
    l = sizeof(struct sockaddr_in);
    d->msg_len = recvfrom(d->listen_fd,
                          d->msg_buf, 512, 0,
                          (struct sockaddr *) &d->client_addr, &l);
    if (d->msg_len < 0) {
        perror("recv from client");
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    } else if (d->msg_len == 0) {
        memset(d, 0, sizeof(struct msg_data));
        return 0;
    }
#ifdef DEBUG
    printf("recv %d bytes from %s:%d\n", d->msg_len,
           inet_ntoa(d->client_addr.sin_addr),
           ntohs(d->client_addr.sin_port));
#endif
    send_to_server(d);
    return 0;
}

int send_to_server(struct msg_data *d)
{
    struct sockaddr_in saddr;

    d->fd = d->srv_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (d->srv_fd < 0) {
        perror("create server socket");
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    }
    int i;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(53);
    for (i = 0;; i++) {
        if (servers[i] == NULL) {
            break;
        }

        saddr.sin_addr.s_addr = inet_addr(servers[i]);

        if (sendto
            (d->srv_fd, d->msg_buf, d->msg_len, 0,
             (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            perror("sendto server");
            close(d->srv_fd);
            memset(d, 0, sizeof(struct msg_data));
            return -1;
        }
    }
#ifdef USE_EPOLL
    struct epoll_event ev;
    ev.data.ptr = d;
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, d->srv_fd, &ev) < 0) {
        perror("add srv_fd");
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    }
#endif
    d->last_active = time(NULL);
#ifdef DEBUG
    printf("send to server success\n");
#endif
    return 0;
}

int recv_from_server(struct msg_data *d)
{
    char buf[512];
    int msg_len;
    msg_len = recvfrom(d->srv_fd, buf, 512, 0, NULL, 0);
    if (msg_len < 0) {
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    } else if (msg_len == 0) {  /* connection closed */
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return 0;
    }

    /* parse the dns message and check the black list */
    do {
        struct dns_msg *m;
        struct dns_rr *rr;
        char *ip;
        char *ip_found;
        int found = 0;

        m = (struct dns_msg *) malloc(sizeof(struct dns_msg));
        if (m == NULL) {
            break;
        }
        memset(m, 0, sizeof(struct dns_msg));
        m->buf = malloc(msg_len);
        if (m->buf == NULL) {
            free(m);
            break;
        }
        memcpy(m->buf, buf, msg_len);
        m->msg_len = msg_len;
        parse_msg(m);
        for (rr = m->an; rr; rr = rr->next) {
            if (rr->type == RR_A) {
                ip = rr->rdata;
                ip_found = strstr(blacklist, ip);
                if (ip_found != NULL) { /* ip is in blacklist */
                    found = 1;
#ifdef DEBUG
                    printf("found bad ip %s, continue.\n", ip);
#endif
                    break;
                }
            }
        }
        free_dns_msg(m);

        if (found) {
            return -1;
        }
    } while (0);
#ifdef DEBUG
    printf("recv %d bytes from server\n", msg_len);
#endif
    send_to_client(d, buf, msg_len);
    return 0;
}

int send_to_client(struct msg_data *d, char *msg, int msg_len)
{

    if (sendto
        (d->listen_fd, msg, msg_len, 0,
         (struct sockaddr *) &d->client_addr,
         sizeof(struct sockaddr_in)) < 0) {
        perror("send to client");
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    }
#ifdef USE_EPOLL
    struct epoll_event ev;
    ev.data.ptr = d;
    ev.events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_DEL, d->srv_fd, &ev);
#endif
#ifdef DEBUG
    printf("send to %s:%d\n", inet_ntoa(d->client_addr.sin_addr),
           htons(d->client_addr.sin_port));
#endif
    close(d->srv_fd);
    memset(d, 0, sizeof(struct msg_data));

    return 0;
}

int main(int argc, char *argv[])
{
    int listen_fd;
    struct sockaddr_in listen_addr;
    printf("dnsproxy (");
#ifdef WIN32
    printf("Win32");
#else
    printf("Linux");
#endif
#ifdef USE_EPOLL
    printf("/epoll");
#else
    printf("/select");
#endif
#ifdef VERSION
    printf(" ver " VERSION ")\n");
#else
    printf(")\n");
#endif

#ifdef WIN32
    /* initial the win32 sockets */
    WSADATA wsaData;
    WSAStartup(0x2020, &wsaData);
#endif

    memset(msg, 0, sizeof(msg));
#ifdef USE_EPOLL
    epfd = epoll_create(MAX_QUEUE);

    if (epfd < 0) {
        perror("epoll_create");
        exit(-1);
    }
#endif
    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd < 0) {
        perror("create listen socket");
        exit(-1);
    }
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(listen_port);
    listen_addr.sin_addr.s_addr = inet_addr(listen_ip);
    if (bind(listen_fd,
             (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind");
        exit(-1);
    }

    msg[MAX_QUEUE].fd = listen_fd;
    msg[MAX_QUEUE].status = 1;
#ifdef USE_EPOLL
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = (void *) &msg[MAX_QUEUE];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        perror("epoll_ctl");
        exit(-1);
    }
#else
    fd_set rfds;
    struct timeval tv;
    int max_fd = listen_fd;
#endif

    int nr_events;
    int i;
    int j;

    /* starting the loop */
    while (1) {
#ifdef USE_EPOLL
        nr_events = epoll_wait(epfd, events, MAX_QUEUE + 1, 3000);
#else                           /* select */
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        for (i = 0; i < MAX_QUEUE; i++) {
            if (msg[i].fd == 0) {
                continue;
            }
            FD_SET(msg[i].fd, &rfds);
            if (msg[i].fd > max_fd) {
                max_fd = msg[i].fd;
            }
        }
        nr_events = select(max_fd + 1, &rfds, NULL, NULL, &tv);
#endif
        if (nr_events < 0) {
#ifdef USE_EPOLL
            perror("epoll_wait");
#else
            perror("select");
#endif
            exit(-1);
        } else if (nr_events == 0) {    /* timeout */
            free_timeout_client();
        }
#ifdef USE_EPOLL
        for (i = 0; i < nr_events; i++) {
            struct msg_data *d;
            d = (struct msg_data *) (events[i].data.ptr);
            if (d->fd == listen_fd) {   /* client request is in */
#else
        if (FD_ISSET(listen_fd, &rfds)) {
#endif
            int retry_count = 0;
          retry:
            for (j = 0; j < MAX_QUEUE; j++) {
                if (msg[j].status == 0) {
                    break;
                }
            }
            if (j == MAX_QUEUE) {
                printf("WARNING: queue is full, retry...\n");
                free_timeout_client();
                if (retry_count) {  /* only retry once */
                    continue;
                }
                retry_count++;
                goto retry;
            }
            msg[j].status = 1;
            msg[j].listen_fd = listen_fd;
            recv_from_client(&msg[j]);
        } else {                /* server response */
#ifdef USE_EPOLL
            recv_from_server(d);
#else
            for (i = 0; i < MAX_QUEUE; i++) {
                if (msg[i].fd == 0) {
                    continue;
                }
                if (FD_ISSET(msg[i].fd, &rfds)) {
                    recv_from_server(&msg[i]);
                }
            }                   /* for */
#endif
       }                        /* if */
#ifdef USE_EPOLL
      }                         /* for */
#endif
    }                           /* while */

    return 0;
}

int free_timeout_client()
{
    time_t now;
    int i;
    now = time(NULL);
    for (i = 0; i < MAX_QUEUE; i++) {
        if (msg[i].status == 0) {
            continue;
        }
        if ((now - msg[i].last_active) > 2) {
            if (msg[i].srv_fd) {
                close(msg[i].srv_fd);
            }
            memset(&msg[i], 0, sizeof(struct msg_data));
        }
    }
    return 0;
}
