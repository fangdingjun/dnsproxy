#============================================
# Filename:
#    dnsproxy.c
# Author:
#    fangdingjun@gmail.com
# License:
#   GPLv3 (http://www.gnu.org/licenses/gpl-3.0.html)
# Description:
#   this is dns proxy server, which forward the client request
#   to more than one upstream dns servers and get the fastest
#   response, than discard the other response
#   there is also has a black list, you can discard the response which
#   contain the ip you don't wanted by the black list
#============================================


#include "dns.h"
#include "dnsproxy.h"

#define MAX_QUEUE 100

/* default remote dns servers */
char *default_servers[] = {
    "8.8.8.8",
    "114.114.114.114",
    "208.67.222.222",
    "1.2.4.8",
    NULL
};

/* default listen ip */
char *listen_ip = "127.0.0.1";

/* default config file name */
char *configfile = "dnsproxy.cfg";

/* default listen port */
int listen_port = 53;

/* log */
FILE *logfp = NULL;

/* server list pointer */
char **servers = default_servers;

/* daemon or not */
int become_daemon = 0;

/* log file name pointer */
char *logfile = "dnsproxy.log";

/* default log level */
int loglevel = 3;

/* the ip lists that china GFW used for DNS cache pollution
*  http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93
*/

/* default file name for black ip list */
char *blacklist = "iplist.txt";

/* pointer to black list */
char *black_ips = NULL;

/* map pointer to config file option name*/
struct arg_map arguments[] = {
    {"listen_ip", ARG_STRING, (void **) &listen_ip},
    {"listen_port", ARG_INT, (void **) &listen_port},
    {"servers", ARG_STR_ARRARY, (void **) &servers},
    {"daemon", ARG_INT, (void **) &become_daemon},
    {"blacklist", ARG_STRING, (void **) &blacklist},
    {"logfile", ARG_STRING, (void **) &logfile},
    {"loglevel", ARG_INT, (void **) &loglevel},
    {NULL, 0, NULL}
};

#ifdef USE_EPOLL
int epfd;
/* epoll events queue */
struct epoll_event events[MAX_QUEUE + 1];
#endif

/* client queue */
struct msg_data msg[MAX_QUEUE + 1];


/* read client request */
int recv_from_client(struct msg_data *d)
{
    socklen_t l;
    l = sizeof(struct sockaddr_in);

    /* read */
    d->msg_len = recvfrom(d->listen_fd,
                          d->msg_buf, 512, 0,
                          (struct sockaddr *) &d->client_addr, &l);
    if (d->msg_len < 0) {
#ifdef WIN32
        perror("recv from client");
#else
        ERR("recv from client failed: %s\n", strerror(errno));
#endif
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    } else if (d->msg_len == 0) {
        memset(d, 0, sizeof(struct msg_data));
        return 0;
    }
    DBG("recv %d bytes from client %s:%d\n", d->msg_len,
        inet_ntoa(d->client_addr.sin_addr),
        ntohs(d->client_addr.sin_port));
    send_to_server(d);
    return 0;
}

/* forward the request to remote dns server */
int send_to_server(struct msg_data *d)
{
    struct sockaddr_in saddr;

    d->fd = d->srv_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (d->srv_fd < 0) {
#ifdef WIN32
        perror("create server socket");
#else
        ERR("create server sokcet error: %s\n", strerror(errno));
#endif
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    }
    int i;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(53);
    int l;
    l=sizeof(saddr);
    for (i = 0;; i++) {
        if (servers[i] == NULL) {
            break;
        }

        saddr.sin_addr.s_addr = inet_addr(servers[i]);

        /* send */
        if (sendto
            (d->srv_fd, d->msg_buf, d->msg_len, 0,
             (struct sockaddr *) &saddr, l) < 0) {
#ifdef WIN32
            perror("sendto server");
#else
            ERR("sendto server failed: %s\n", strerror(errno));
#endif
            close(d->srv_fd);
            memset(d, 0, sizeof(struct msg_data));
            return -1;
        }
        DBG("send to %s:%d success\n",
                inet_ntoa(saddr.sin_addr),
                htons(saddr.sin_port));
    }
#ifdef USE_EPOLL
    struct epoll_event ev;
    ev.data.ptr = d;
    ev.events = EPOLLIN;

    /* add to epoll watch list */
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, d->srv_fd, &ev) < 0) {
        ERR("add srv_fd failed: %s\n", strerror(errno));
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    }
#endif

    /* record the time */
    d->last_active = time(NULL);
    DBG("send to server success\n");
    return 0;
}

/* read server response */
int recv_from_server(struct msg_data *d)
{
    char buf[512];
    int msg_len;
    struct sockaddr_in saddr;
    socklen_t l;
    memset(&saddr, 0, sizeof(saddr));
    l=sizeof(saddr);

    /* read */
    msg_len = recvfrom(d->srv_fd, buf, 512, 0, (struct sockaddr*) &saddr, &l);
    if (msg_len < 0) {
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    } else if (msg_len == 0) {
        /* server connection closed */
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return 0;
    }

    DBG("recv %d bytes from server %s:%d\n", msg_len,
            inet_ntoa(saddr.sin_addr),
            htons(saddr.sin_port)
            );

    /* parse the dns message and check the black list */
    do {
        struct dns_msg *m;
        struct dns_rr *rr;
        char *ip;
        char *ip_found;
        int found = 0;

        /* no list loaded */
        if (!black_ips)
            break;

        /* allocate memory */
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

        /* prepare */
        memcpy(m->buf, buf, msg_len);
        m->msg_len = msg_len;

        /* parse */
        parse_msg(m);

        /* check */
        for (rr = m->an; rr; rr = rr->next) {
            if (rr->type == RR_A) {
                ip = rr->rdata;
                ip_found = strstr(black_ips, ip);
                if (ip_found != NULL) { /* ip is in blacklist */
                    found = 1;
                    WARN("found bad ip %s, continue.\n", ip);
                    break;
                }
            }
        }

        /* free memory */
        free_dns_msg(m);

        if (found) {
            /* ignore the response */
            return -1;
        }
    } while (0);

    send_to_client(d, buf, msg_len);
    return 0;
}

/* answer the client */
int send_to_client(struct msg_data *d, char *msg, int msg_len)
{

    /* send */
    if (sendto
        (d->listen_fd, msg, msg_len, 0,
         (struct sockaddr *) &d->client_addr,
         sizeof(struct sockaddr_in)) < 0) {
        /* on error */
#ifdef WIN32
        perror("send to client");
#else
        ERR("send to client failed: %s\n", strerror(errno));
#endif
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    }

    /* now we get a good result, we ignore the response from other server */

#ifdef USE_EPOLL
    struct epoll_event ev;
    ev.data.ptr = d;
    ev.events = EPOLLIN;

    /* remove from epoll watch list */
    epoll_ctl(epfd, EPOLL_CTL_DEL, d->srv_fd, &ev);
#endif

    DBG("send to %s:%d success\n", inet_ntoa(d->client_addr.sin_addr),
        htons(d->client_addr.sin_port));

    close(d->srv_fd);
    memset(d, 0, sizeof(struct msg_data));

    return 0;
}

void usage(char *progname)
{
    printf("%s OPTIONS\n", progname);
    printf("options:\n");
    printf("    -h        show this message\n"
           "    -c FILE   load config from FILE\n"
           "    -d        run in daemon mode\n"
           "    -l IP     listen on IP\n"
           "    -p PORT   listen on PORT\n"
           "    -g LEVEL  set loglevel to LEVEL\n"
           "    -f FILE   write log to FILE\n");
}

int parse_cmdline(int argc, char *argv[], int times)
{
    int i;
    if (argc < 2)
        return 0;
    for (i = 1; i < argc;) {
        if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-c") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "-c need an argument\n");
                usage(argv[0]);
                exit(-1);
            }

            /* we ignore the config file on second time */
            if (times < 2) {
                configfile = argv[i];
            }
            i++;
        } else if (strcmp(argv[i], "-d") == 0) {
            become_daemon = 1;
            i++;
        } else if (strcmp(argv[i], "-l") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "-l need a argument\n");
                usage(argv[0]);
                exit(-1);
            }
            listen_ip = argv[i];
            i++;
        } else if (strcmp(argv[i], "-p") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "-p need a argument\n");
                usage(argv[0]);
                exit(-1);
            }
            listen_port = atoi(argv[i]);
            i++;
        } else if (strcmp(argv[i], "-g") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "-g need a argument\n");
                usage(argv[0]);
                exit(-1);
            }
            loglevel = atoi(argv[i]);
            i++;
        } else if (strcmp(argv[i], "-f") == 0) {
            i++;
            if (i >= argc) {
                fprintf(stderr, "-f need a argument\n");
                usage(argv[0]);
                exit(-1);
            }
            logfile = argv[i];
            i++;
        } else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            i++;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int listen_fd;
    int i;
    int j;
    struct sockaddr_in listen_addr;

    logfp=stdout;

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

    /* parse cmdline */
    parse_cmdline(argc, argv, 1);

    /* parse config file */
    parse_cfg(configfile, arguments);

    /* parse cmdline again, the command line option has high priority*/
    parse_cmdline(argc, argv, 2);

    if (blacklist) {
        /* read black list */
        get_blackip(blacklist, &black_ips);
    }

    INFO("listen to %s:%d\n", listen_ip, listen_port);

    for (i=0; servers[i] != NULL; i++){
        INFO("add server %s to remote list\n", servers[i]);
    }

    INFO("use blacklist: %s\n", blacklist);
    INFO("logfile: %s\n", logfile);
    INFO("loglevel: %d\n", loglevel);
    INFO("daemon: %d\n", become_daemon);

    if (logfile) {
        if (strcmp(logfile, "stdout") == 0
            || strcmp(logfile, "stderr") == 0) {
            logfp = stdout;
        } else {
            logfp = fopen(logfile, "a");
            if (logfp == NULL) {
                //perror(logfile);
                fprintf(stderr, "open %s failed\n", logfile);
            }
        }
    }
    if (become_daemon) {
        INFO("run in backgroud...\n");
#ifdef WIN32
        FreeConsole();
#else
        daemon(1, 1);
#endif
        freopen(NULLDEV, "w", stdout);
        freopen(NULLDEV, "w", stderr);
    }
#ifdef WIN32
    /* initial the win32 sockets */
    WSADATA wsaData;
    WSAStartup(0x2020, &wsaData);
#endif

    /* initial global arrary */
    memset(msg, 0, sizeof(msg));

#ifdef USE_EPOLL
    /* epoll fd */
    epfd = epoll_create(MAX_QUEUE);

    if (epfd < 0) {
        ERR("epoll_create failed: %s\n", strerror(errno));
        exit(-1);
    }
#endif

    /* listen socket */
    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd < 0) {
#ifdef WIN32
        perror("create listen socket");
#else
        ERR("create listen socket failed: %s\n", strerror(errno));
#endif
        exit(-1);
    }

    DBG("create listen socket success\n");

#ifdef WIN32
    {
        /* avoid errno 10054 on udp socket */
        int reported = 0;
        DWORD ret = 0;
        int status = WSAIoctl(listen_fd, SIO_UDP_CONNRESET, &reported,
                              sizeof(reported), NULL, 0, &ret, NULL, NULL);
        if (status == SOCKET_ERROR) {
            perror("SIO_UDP_CONNRESET");
            exit(-1);
        }
        INFO("SIO_UDP_CONNRESET ioctl success\n");
    }
#endif

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(listen_port);
    listen_addr.sin_addr.s_addr = inet_addr(listen_ip);
    if (bind(listen_fd,
             (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
#ifdef WIN32
        perror("bind");
#else
        ERR("bind error: %s\n", strerror(errno));
#endif
        exit(-1);
    }

    INFO("bind success\n");

    msg[MAX_QUEUE].fd = listen_fd;
    msg[MAX_QUEUE].status = 1;
#ifdef USE_EPOLL
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = (void *) &msg[MAX_QUEUE];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        ERR("epoll_ctl failed: %s", strerror(errno));
        exit(-1);
    }
#else
    fd_set rfds;
    struct timeval tv;
    int max_fd = listen_fd;
#endif

    int nr_events;

    /* starting the loop */
    while (1) {
#ifdef USE_EPOLL
        /* epoll */
        nr_events = epoll_wait(epfd, events, MAX_QUEUE + 1, 3000);
#else
        /* select */
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
            ERR("epoll_wait failed: %s\n", strerror(errno));
#else
            perror("select");
#endif
            exit(-1);
        } else if (nr_events == 0) {    /* timeout */
            free_timeout_client();
            continue;
        }

        DBG("%d events occured\n", nr_events);

#ifdef USE_EPOLL
        /* epoll */
        for (i = 0; i < nr_events; i++) {
            struct msg_data *d;
            d = (struct msg_data *) (events[i].data.ptr);
            if (d->fd == listen_fd) {   /* client request is in */
#else
        /* check if listen socket */
        if (FD_ISSET(listen_fd, &rfds)) {
#endif
            int retry_count = 0;
          retry:
            for (j = 0; j < MAX_QUEUE; j++) {
                if (msg[j].status == 0) {
                    break;
                }
            }

            /* no buffer free */
            if (j == MAX_QUEUE) {
                WARN("WARNING: queue is full, retry...\n");
                free_timeout_client();
                if (retry_count) {  /* only retry once */
                    continue;
                }
                retry_count++;
                goto retry;
            }
            msg[j].status = 1;
            msg[j].listen_fd = listen_fd;

            /* process request */
            recv_from_client(&msg[j]);

        } else {                /* server response */
#ifdef USE_EPOLL
            recv_from_server(d);
#else
            /* select */
            for (i = 0; i < MAX_QUEUE; i++) {
                if (msg[i].fd == 0) {
                    continue;
                }
                if (FD_ISSET(msg[i].fd, &rfds)) {
                    /* process server response */
                    recv_from_server(&msg[i]);
                }
            }   /* for */
#endif
        }    /* if */
#ifdef USE_EPOLL
    }    /* for */
#endif
    }    /* while */

    return 0;
} /* main */

int free_timeout_client()
{
    time_t now;
    int i;
    now = time(NULL);
    for (i = 0; i < MAX_QUEUE; i++) {
        if (msg[i].status == 0) {
            continue;
        }

        /* time expires */
        if ((now - msg[i].last_active) > 2) {
            if (msg[i].srv_fd) {
                DBG("timeout, close fd %d\n", msg[i].srv_fd);
                close(msg[i].srv_fd);
            }
            memset(&msg[i], 0, sizeof(struct msg_data));
        }
    }
    return 0;
}
