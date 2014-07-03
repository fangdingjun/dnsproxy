/*
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
*/

#include "dns.h"
#include "dnsproxy.h"
#include "cache.h"
#include <stdlib.h>
#include <ldns/ldns.h>

#define MAX_QUEUE 100

sqlite3 *init_dns_cache(char *dbname, char *tblname);
int process_cache(struct msg_data *d);
int str2label(const char *, char *);

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

/* sqlite connection */
sqlite3 *db = NULL;
char *cache_table = "dns";
char *dbname = ":memory:";

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
#if 0     
    /* lookup for cache */    
     
    if (process_cache(d) == 0) {
        return 0;
    }
#endif
    
    
    /* no cache, query upstream server */
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
    l = sizeof(saddr);
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
            inet_ntoa(saddr.sin_addr), htons(saddr.sin_port));
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
    l = sizeof(saddr);

    /* read */
    msg_len =
        recvfrom(d->srv_fd, buf, 512, 0, (struct sockaddr *) &saddr, &l);
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
        inet_ntoa(saddr.sin_addr), htons(saddr.sin_port)
        );

    /* parse the dns message and check the black list */
    do {
        //struct dns_msg *m;
        //struct dns_rr *rr;
        char *ip;
        char *ip_found;
        int found = 0;
        int i;
        ldns_buffer *b=NULL; 
        ldns_pkt *p=NULL;
        ldns_rr_list *an;
        ldns_rr *rr;
        ldns_rdf *rdf;
        /* no list loaded */
        if (!black_ips)
            break;

        b=LDNS_MALLOC(ldns_buffer);
        if(!b){
            ERR("allocate buffer failed\n");
            goto done;
        }

        ldns_buffer_new_frm_data(b,buf,msg_len);

        /* parse dns message */
        if(ldns_buffer2pkt_wire(&p, b) != LDNS_STATUS_OK){
            ERR("parse dns packet failed\n");
            /* ignore the packet */
            found = 1;
            goto done;
        }

        /* check response code */
        if (ldns_pkt_get_rcode(p) == LDNS_RCODE_SERVFAIL ||
                ldns_pkt_get_rcode(p) == LDNS_RCODE_REFUSED){

            /* ignore the response when server fail */
            found = 1;
            goto done;
        }

        if (ldns_pkt_ancount(p)){
            an = ldns_pkt_answer(p);
            if(logfp){
                ldns_rr_list_print(logfp,an);
            }
        }else{
            goto done;
        }

        for (i=0; i< ldns_pkt_ancount(p); i++){
            rr=ldns_rr_list_rr(an, i);
            if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A){
                ldns_buffer *out;
                //char *ip;
                //char *p1;
                out=ldns_buffer_new(20);
                if (!out){
                    ERR("new buffer failed\n");
                    goto done;
                }
                rdf = ldns_rr_a_address(rr);
                if (ldns_rdf2buffer_str_a(out, rdf) != LDNS_STATUS_OK){
                    ERR("rdf2buffer_str_a failed\n");
                    ldns_buffer_free(out);
                    goto done;
                }
                ip=ldns_buffer_export2str(out);
                if(ip == NULL){
                    ERR("buffer export failed\n");
                    ldns_buffer_free(out);
                    goto done;
                }
                ldns_buffer_free(out);
                ip_found=strstr(black_ips, ip);
                if(ip_found){
                    DBG("fond bad ip %s\n", ip);
                    found = 1;
                    LDNS_FREE(ip);
                    goto done;
                }
                LDNS_FREE(ip);
            }
        }

#if 0
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
                DBG("%s IN A %s\n", rr->name, (char *) rr->rdata);
                ip = rr->rdata;
                ip_found = strstr(black_ips, ip);
                if (ip_found != NULL) { /* ip is in blacklist */
                    found = 1;
                    WARN("found bad ip %s, continue.\n", ip);
                    break;
                }
            } else if (rr->type == RR_AAAA) {
                DBG("%s IN AAAA %s\n", rr->name, (char *) rr->rdata);
            } else if (rr->type == RR_CNAME) {
                DBG("%s IN CNAME %s\n", rr->name, (char *) rr->rdata);
            }
        }
        if (!found) {
            cache_store(db, cache_table, m->an);
        }
        

        /* free memory */
        free_dns_msg(m);
#endif
done:
        if (b){
            ldns_buffer_free(b);
        }
        if(p){
            ldns_pkt_free(p);
        }

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

    logfp = stdout;

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

    /* parse cmdline again, the command line option has high priority */
    parse_cmdline(argc, argv, 2);

    if (blacklist) {
        /* read black list */
        get_blackip(blacklist, &black_ips);
    }
    db = init_dns_cache(dbname, cache_table);

    INFO("listen to %s:%d\n", listen_ip, listen_port);

    for (i = 0; servers[i] != NULL; i++) {
        INFO("add server %s to remote list\n", servers[i]);
    }

    INFO("use blacklist: %s\n", blacklist);
    INFO("logfile: %s\n", logfile);
    INFO("loglevel: %d\n", loglevel);
    INFO("daemon: %d\n", become_daemon);

    /* init random seed */
    srand(time(NULL));
    
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

        } else {
            /* server response */
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
          /* for */
            }
#endif
       /* if */
        }
#ifdef USE_EPOLL
        /* for */
        }
#endif
    /* while */
    }

    return 0;
/* main */
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

        /* time expires */
        if ((now - msg[i].last_active) > 2) {
            if (msg[i].srv_fd) {
                DBG("timeout, close fd %d\n", msg[i].srv_fd);
                close(msg[i].srv_fd);
            }
            memset(&msg[i], 0, sizeof(struct msg_data));
        }
    }
    delete_expired(db, cache_table);
    //DBG("delete expired cache success.\n");
    return 0;
}

sqlite3 *init_dns_cache(char *dbname, char *tblname)
{
    sqlite3 *dbc;
    if (dbname == NULL || tblname == NULL) {
        WARN("dbname or table name is NULL\n");
        return NULL;
    }

    dbc = open_db(dbname);
    if (dbc == NULL) {
        return NULL;
    }
    init_cache(dbc, 12 * 1024 * 1024);
    if (create_cache_table(dbc, tblname) != 0) {
        WARN("create table %s failed\n", tblname);
    }
    return dbc;
}

int process_cache(struct msg_data *d)
{
    struct dns_msg *m;
    struct dns_rr *r;
    struct dns_rr *r1;
    char buf[512];
    struct msg_header *h;
    int ret = 0;
    size_t offset;
    int ancount = 0;
    char *pos;
    unsigned short flags;
    char label[100];
    char *p1;
    char *lbl_p;

    if (db == NULL) {
        return -1;
    }

    m = malloc(sizeof(struct dns_msg));
    if (m == NULL) {
        ERR("out of memory\n");
        return -1;
    }
    memset(m, 0, sizeof(struct dns_msg));

    m->buf = malloc(d->msg_len);
    if (m->buf == NULL) {
        ERR("out of memory\n");
        ret = -1;
        goto err1;
    }
    memcpy(m->buf, d->msg_buf, d->msg_len);
    m->msg_len = d->msg_len;

    parse_msg(m);

    if (m->qd == NULL || m->qd->name == NULL) {
        ret = -1;
        goto err1;
    }

    DBG("query %s IN 0x%02x\n", m->qd->name, m->qd->type);

    r = cache_fetch(db, cache_table, m->qd->name, m->qd->type);
    if (r == NULL) {
        ret = -1;
        goto err1;
    }

    for (r1 = r; r1 != NULL; r1 = r1->next) {
        ancount++;
    }

    if (ancount == 0) {
        ret = -1;
        goto err1;
    }

    DBG("cache: ancount %d\n", ancount);

    memcpy(buf, d->msg_buf, 12);
    h = (struct msg_header *) buf;
    h->qdcount = htons(1);
    h->ancount = htons(ancount);
    h->nscount = 0;
    h->arcount = 0;

    flags = 0;

    p1 = (char *) &flags;
    p1[0] |= ((1 << 7) | 0x1);  /* rq rd */
    p1[1] |= (1 << 7);          /* ra */

    h->flags = flags;

    //DBG("flags: 0x%04x\n", flags);
    pos = buf + 12;
    offset = str2label(m->qd->name, label);
    memcpy(pos, label, offset);
    //offset = set_qname(pos,m->qd->name);
    pos += offset;
    *((unsigned short *) pos) = htons(m->qd->type);
    pos += 2;
    *((unsigned short *) pos) = htons(m->qd->cls);
    pos += 2;

    int i;
    struct dns_rr *first;
    struct dns_rr *cur;
    int rand_start = rand() % ancount;
    cur = first = r;

    for (i = 0; i < rand_start; i++) {
        cur = cur->next;
    }

    r1 = cur;
    while (1) {
        if (r1 == NULL) {
            ERR("first record is NULL\n");
            break;
        }
        offset = str2label(r1->name, label);
        if ((lbl_p = strstr(buf, label)) != NULL) {
            int f = lbl_p - buf;
            f |= (0xc0 << 8);
            *((unsigned short *) pos) = htons(f);
            pos += 2;
        } else {
            memcpy(pos, label, offset);
            pos += offset;
        }
        if ((pos - buf) >= 504) {
            ERR("out of buffer\n");
            goto err2;
        }
        *((unsigned short *) pos) = htons(r1->type);
        pos += 2;
        *((unsigned short *) pos) = htons(r1->cls);
        pos += 2;
        *((unsigned int *) pos) = htonl(r1->ttl);
        pos += 4;
        if (r1->type == RR_A) {
            *((unsigned short *) pos) = htons(4);
            pos += 2;
#ifdef WIN32
            struct sockaddr_storage sa;
            struct sockaddr_in *sin = (struct sockaddr_in *) &sa;
            memset(&sa, 0, sizeof(sa));
            sa.ss_family = AF_INET;
            int addlen = sizeof(*sin);

            WSAStringToAddress(r1->rdata, AF_INET, NULL, (LPSOCKADDR) sin,
                               &addlen);
            memcpy(pos, (void *) &sin->sin_addr, 4);

#else
            inet_pton(AF_INET, r1->rdata, pos);
#endif
            pos += 4;
        } else if (r1->type == RR_AAAA) {
            *((unsigned short *) pos) = htons(16);
            pos += 2;
#ifdef WIN32
            struct sockaddr_storage sa;
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sa;
            int addlen = sizeof(*sin6);
            memset(&sa, 0, sizeof(sa));
            sa.ss_family = AF_INET6;
            WSAStringToAddress(r1->rdata, AF_INET6, NULL,
                               (LPSOCKADDR) sin6, &addlen);
            memcpy(pos, (void *) &sin6->sin6_addr, 16);
#else
            inet_pton(AF_INET6, r1->rdata, pos);
#endif
            pos += 16;
        } else if (r1->type == RR_CNAME) {
            offset = str2label(r1->rdata, label);
            *((unsigned short *) pos) = htons(offset);
            pos += 2;
            memcpy(pos, label, offset);
            pos += offset;
        } else {
            ERR("unknown type\n");
            ret = -1;
            goto err2;
        }
        r1 = r1->next;
        if (r1 == NULL) {
            r1 = first;
        }
        if (r1 == cur)
            break;
    }

    if (sendto
        (d->listen_fd, buf, pos - buf, 0,
         (struct sockaddr *) &d->client_addr,
         sizeof(struct sockaddr_in)) < 0) {
#ifdef WIN32
        perror("send to");
#else
        ERR("sendto client error: %s\n", strerror(errno));
#endif
        ret = -1;
        goto err2;
    }

    DBG("send to client %s:%d success from cache.\n",
        inet_ntoa(d->client_addr.sin_addr), ntohs(d->client_addr.sin_port)
        );

    ret = 0;
    memset(d, 0, sizeof(struct msg_data));

  err2:
    free_rr(r);

  err1:
    free_dns_msg(m);
    return ret;
}
