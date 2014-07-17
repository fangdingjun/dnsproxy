#include <ldns/config.h>
#include <ldns/ldns.h>

#if WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#else
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>

#include <sqlite3.h>

#include <time.h>

#include "cache.h"
#include "dns.h"
#include "dnsproxy.h"

#define MAX_CLIENT 100

struct client {

    /* listen sock */
    int listen_sock;

    /* socket to send request to server */
    int srv_sock;

    /* client message length */
    size_t msg_len;

    /* used or not */
    int status;

    /* time */
    time_t last_time;

    /* client address */
    struct sockaddr_in client_addr;
    //char buf[512];
};

/* black ip lists */
char *black_ips = NULL;

int get_blackip(char *, char **);

struct client clients[MAX_CLIENT];
int sendto_server(struct client *c, const uint8_t * data);

int set_udp_sock_option(int sock_fd);

int listen_sock_udp(const char *addr, uint16_t port);

/* default servers */
char *default_servers[] = {
    "202.180.160.1",
    "202.45.84.59",
    "202.45.84.67",
    "1.2.4.8",
    /*"8.8.8.8", */
    "114.114.114.114",
    "4.2.2.2",
    "223.5.5.5",
    //"192.168.1.1",
    NULL
};

/* sqlite3 handle */
sqlite3 *db = NULL;

/* dns cache file */
char *cache_file = ":memory:";

/* dns cache table */
char *cache_table = "dns";

/* max cache size */
size_t max_cache = 4 * 1024 * 1024;

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

/* black ip list file name*/
char *blacklist = "iplist.txt";

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

#ifdef WIN32
#define log_err(msg) perror(msg)
#else
#define log_err(msg) ERR(msg ": %s\n", strerr(errno))
#endif

int listen_sock_udp(const char *addr, uint16_t port)
{
    int sock;
    struct sockaddr_in local_addr;
    char *default_addr = "0.0.0.0";
    uint16_t default_port = 53;

    if (addr == NULL) {
        addr = default_addr;
    }

    if (port == 0) {
        port = default_port;
    }
    
    DBG("listen to %s:%d\n", addr, port);

    memset(&local_addr, 0, sizeof(local_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = inet_addr(addr);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_err("create socket failed");
        return -1;
    }

    DBG("create listen socket success\n");

    //printf("socket success\n");
    if (bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr)) <
        0) {
        log_err("bind failed");
        close(sock);
        return -1;
    }

    DBG("bind success, socket fd = %d\n", sock);
    //printf("bind success\n");
    //printf("success creat sock fd=%d\n", sock);
    return sock;
}

inline int set_read_fd(int listen_fd, fd_set * r)
{
    int i;
    int max = listen_fd;

    /* clear fdset */
    FD_ZERO(r);

    /* add listen socket */
    FD_SET(listen_fd, r);

    /* add other socket */
    for (i = 0; i < MAX_CLIENT; i++) {
        if (clients[i].status == 0) {
            continue;
        }

        if (clients[i].srv_sock > max) {
            max = clients[i].srv_sock;
        }
        DBG("add fd %d to select list\n", clients[i].srv_sock);
        FD_SET(clients[i].srv_sock, r);
    }
    return max;
}

struct client *get_free_client()
{
    int i;
    for (i = 0; i < MAX_CLIENT; i++) {
        if (clients[i].status == 0) {
            break;
        }
    }

    /* all queue are used */
    if (i == MAX_CLIENT) {
        return NULL;
    }

    return (struct client *) &clients[i];
}

int free_timeout_client()
{
    int i;
    time_t now;
    now = time(NULL);
    for (i = 0; i < MAX_CLIENT; i++) {
        if (clients[i].status == 1) {
            if ((now - clients[i].last_time) > 3) {
                DBG("close socket %d\n", clients[i].srv_sock);
                close(clients[i].srv_sock);
                clients[i].status = 0;
            }
        }
    }
    delete_expired_rr(db, cache_table);
    return 0;
}

int reply_from_cache(struct client *c, const uint8_t * data)
{
    ldns_pkt *p = NULL;
    ldns_buffer *b = NULL;
    int ret = 0;
    ldns_rr_list *q = NULL;
    ldns_rr_list *an = NULL;
    ldns_pkt *pkt_an = NULL;
    ldns_buffer *buf_an = NULL;
    int i;

    b = LDNS_MALLOC(ldns_buffer);
    ldns_buffer_new_frm_data(b, (void *) data, c->msg_len);
    if (ldns_buffer2pkt_wire(&p, b) != LDNS_STATUS_OK) {
        ERR("parse pkt failed\n");
        ret = -1;
        goto err1;
    }

    q = ldns_pkt_question(p);
    if (q == NULL) {
        ret = -1;
        goto err1;
    }
    //DBG("query:\n");
    //ldns_rr_print(stdout, ldns_rr_list_rr(q,0));
    //ldns_pkt_print(stdout, p);
    an = lookup_cache(ldns_rr_list_rr(q, 0), db, cache_table);
    if (an == NULL) {
        ret = -1;
        goto err1;
    }
    
    DBG("found %d record from cache\n", ldns_rr_list_rr_count(an));

    //DBG("query db return\n");
    pkt_an = ldns_pkt_new();
    ldns_pkt_set_id(pkt_an, ldns_pkt_id(p));
    //ldns_pkt_set_flags(pkt_an, LDNS_RD|LDNS_RA|LDNS);
    //ldns_pkt_set_answer(pkt_an, an);

    /* copy to reply pkt answer section */
    for (i = 0; i < ldns_rr_list_rr_count(an); i++) {
        ldns_rr_list_push_rr(ldns_pkt_answer(pkt_an),
                             ldns_rr_clone(ldns_rr_list_rr(an, i)));
    }

    /* copdy to reply pkt question section */
    for (i = 0; i < ldns_rr_list_rr_count(q); i++) {
        ldns_rr_list_push_rr(ldns_pkt_question(pkt_an),
                             ldns_rr_clone(ldns_rr_list_rr(q, i)));
    }

    ldns_pkt_set_rcode(pkt_an, LDNS_RCODE_NOERROR);
    ldns_pkt_set_opcode(pkt_an, LDNS_PACKET_QUERY);

    /* flags */
    ldns_pkt_set_qr(pkt_an, 1);
    ldns_pkt_set_rd(pkt_an, 1);
    ldns_pkt_set_ra(pkt_an, 1);

    //ldns_pkt_set_question(pkt_an,ldns_pkt_question(p));

    ldns_pkt_set_qdcount(pkt_an, 1);
    ldns_pkt_set_ancount(pkt_an, ldns_rr_list_rr_count(an));
    ldns_pkt_set_nscount(pkt_an, 0);
    ldns_pkt_set_arcount(pkt_an, 0);

    buf_an = ldns_buffer_new(1024);
    ldns_pkt2buffer_wire(buf_an, pkt_an);
    
    DBG("cache: send to client\n");

    if (sendto
        (c->listen_sock, (char *) ldns_buffer_begin(buf_an),
         ldns_buffer_position(buf_an), 0,
         (struct sockaddr *) &c->client_addr,
         sizeof(c->client_addr)) < 0) {
        ret = -1;
        log_err("send to client failed");
        goto err2;
    }
    //DBG("answer from cache:\n");

    //ldns_pkt_print(stdout, pkt_an);
    ret = 1;
  err2:
    ldns_buffer_free(buf_an);
    ldns_pkt_free(pkt_an);
    ldns_rr_list_deep_free(an);
  err1:
    ldns_buffer_free(b);
    ldns_pkt_free(p);
    return ret;
}

int process_client_request(struct client *c)
{
    //uint8_t *data;
    char data[512];
    socklen_t s = sizeof(c->client_addr);
    int s1;
    /*
       data = ldns_udp_read_wire(c->listen_sock, &s1,
       (struct sockaddr_storage *) &c->client_addr,
       &s);
     */
    if ((s1 = recvfrom(c->listen_sock, data, 512, 0,
                       (struct sockaddr *) &c->client_addr, &s)) < 0) {
        c->status = 0;
        log_err("error occured when read from client");
        return -1;
    }
    //printf("read %d bytes from client\n", s1);
    DBG("receive %d bytes from client\n", s1);
    c->msg_len = s1;

    if (db) {
        if (reply_from_cache(c, (uint8_t *) data) > 0) {
            DBG("reply from cache success\n");
            c->status = 0;
            return 0;
        }
    }
    
    DBG("forward request to server\n");
    sendto_server(c, (uint8_t *) data);
    //free(data);
    return 0;
}

int sendto_server(struct client *c, const uint8_t * data)
{
    int sock;
    struct sockaddr_in srv_addr;

    int i;


    memset(&srv_addr, 0, sizeof(srv_addr));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(53);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0){
        log_err("create server socket failed");
        c->status = 0;
        return -1;
    }

    set_udp_sock_option(sock);

    i = 0;
    while (servers[i] != NULL) {
        srv_addr.sin_addr.s_addr = inet_addr(servers[i]);
        //printf("send to %s\n", servers[i]);
        if (sendto(sock, (char *) data, c->msg_len, 0,
               (struct sockaddr *) &srv_addr, sizeof(srv_addr)
            ) < 0){
            log_err("send to server failed");
        }
        i++;
    }

    c->srv_sock = sock;
    c->last_time = time(NULL);

    return 0;
}

inline int check_listen_fd(int listen_fd, fd_set * r)
{
    struct client *c;
    if (FD_ISSET(listen_fd, r)) {
        c = get_free_client();
        if (c == NULL) {
            return -1;
        }

        c->listen_sock = listen_fd;
        c->status = 1;
        process_client_request(c);
    }
    return 0;
}

int match_black_list(ldns_rr * r)
{
    ldns_rdf *d;
    ldns_buffer *b;
    char ip[20];
    int len;
    int ret = 0;
    if (!black_ips) {
        return 0;
    }

    b = ldns_buffer_new(20);
    if (!b) {
        goto err1;
    }
    d = ldns_rr_a_address(r);
    if (!d) {
        goto err1;
    }
    ldns_rdf2buffer_str_a(b, d);
    len = ldns_buffer_position(b);
    strncpy(ip, (char *) ldns_buffer_begin(b), len);
    ip[len] = '\0';
    if (strstr(black_ips, ip) != NULL) {
        DBG("%s is in blacklist\n", ip);
        ret = 1;
    }
  err1:
    ldns_buffer_free(b);

    return ret;
}

int process_srv_response(struct client *c)
{
    //uint8_t *data = NULL;
    //size_t s = 0;
    size_t s1 = 512;
    ldns_pkt *p = NULL;
    ldns_buffer *b = NULL;

    int i;

    ldns_rr_list *an;
    ldns_rr *a;

    int ret = 0;

    uint8_t rcode;
    char data[512];
    int ancount = 0;

    //data = ldns_udp_read_wire(c->srv_sock, &s1, NULL, &s);
    if ((s1 = recvfrom(c->srv_sock, data, 512, 0, NULL, NULL)) < 0) {
        log_err("error occured when read from server");
        goto err1;
    }

    DBG("receive %d bytes from server\n", s1);

    b = LDNS_MALLOC(ldns_buffer);

    ldns_buffer_new_frm_data(b, data, s1);

    ldns_buffer2pkt_wire(&p, b);

    if (p == NULL) {
        goto err1;
    }

    rcode = ldns_pkt_get_rcode(p);
    if (rcode == LDNS_RCODE_SERVFAIL || rcode == LDNS_RCODE_REFUSED) {
        DBG("SERVERFAIL response, ignore\n");
        goto err1;
    }

    ancount = ldns_pkt_ancount(p);
    
    DBG("server response %d answers\n", ancount);


    an = ldns_pkt_answer(p);

    for (i = 0; i < ancount; i++) {
        a = ldns_rr_list_rr(an, i);
        switch (ldns_rr_get_type(a)) {
        case LDNS_RR_TYPE_A:
            if (match_black_list(a)) {
                ret = -1;
                goto err1;
            }
            break;
        default:
            ;
        }
    }

    if (db) {
        DBG("cache records\n");
        cache_rr(an, db, cache_table);
    }

    if (sendto(c->listen_sock, (char *) data, s1, 0,
               (struct sockaddr *) &c->client_addr,
               sizeof(c->client_addr)) < 0) {
        log_err("error occoured when send to client");
        ret = -1;
        goto err1;
    }

    DBG("send to client success\n");

    c->status = 0;

    close(c->srv_sock);

    ret = 0;

  err1:

    ldns_buffer_free(b);
    ldns_pkt_free(p);

    return ret;
}

inline int check_srv_fd(fd_set * r)
{
    int i;
    for (i = 0; i < MAX_CLIENT; i++) {
        if (clients[i].status == 0) {
            continue;
        }
        if (FD_ISSET(clients[i].srv_sock, r)) {
            process_srv_response(&clients[i]);
        }
    }
    return 0;
}

inline int set_udp_sock_option(int sock_fd)
{

#ifdef WIN32

    /* avoid errno 10054 on udp socket */
    int reported = 0;
    DWORD ret = 0;
    int status = WSAIoctl(sock_fd, SIO_UDP_CONNRESET, &reported,
                          sizeof(reported), NULL, 0, &ret, NULL, NULL);
    if (status == SOCKET_ERROR) {
        //perror("SIO_UDP_CONNRESET");
        log_err("ioctl failed");
        //exit(-1);
    }
    //INFO("SIO_UDP_CONNRESET ioctl success\n");

#endif
    return 0;
}

inline void sock_init()
{
#ifdef WIN32

    DBG("initial win32 sockets\n");
    /* initial the win32 sockets */
    WSADATA wsaData;
    WSAStartup(0x2020, &wsaData);
#endif
}

inline int daemon_init(){
    if (become_daemon){
        DBG("run in daemon mode\n");
#if WIN32
        FreeConsole();
#else
        daemon(1, 1);
#endif
        DBG("redirect output to NULL device\n");
        freopen(NULLDEV, "w", stdout);
        freopen(NULLDEV, "w", stderr);
    }

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
    int listen_sock;
    fd_set rfds;
    struct timeval tv;
    int nr;
    //int i;

    /* parse cmdline */
    parse_cmdline(argc, argv, 1);

    DBG("parse configure file\n");

    /* parse config file */
    parse_cfg(configfile, arguments);

    /* parse cmdline again, the command line option has high priority */
    parse_cmdline(argc, argv, 2);

    if (blacklist) {

        DBG("read black ip list\n");

        /* read black list */
        get_blackip(blacklist, &black_ips);
    }

    logfp = stdout;

    if (logfile) {
        if (strcmp(logfile, "stdout") == 0
            || strcmp(logfile, "stderr") == 0) {
            logfp = stdout;
        } else {
            logfp = fopen(logfile, "a");
            if (logfp == NULL) {
                logfp = stdout;
                fprintf(stderr, "open %s failed\n", logfile);
            }
        }
    }

    sock_init();

    db = NULL;

    db = cache_init(cache_file, cache_table, max_cache);

    memset(&clients, 0, sizeof(clients));

    //printf("begin to create socket...\n");
    listen_sock = listen_sock_udp(NULL, 0);
    if (listen_sock < 0) {
        return -1;
    }

    set_udp_sock_option(listen_sock);

    //printf("listen success\n");
    //printf("begin to accept connection...\n");
    daemon_init();

    while (1) {
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        int max_fd = set_read_fd(listen_sock, &rfds);
        nr = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (nr < 0) {
            log_err("select failed");
            return -1;
        } else if (nr == 0) {
            /* timeout */
            free_timeout_client();
        } else {
            //printf("%d events\n", nr);
            check_listen_fd(listen_sock, &rfds);
            check_srv_fd(&rfds);
        }
    }

    close(listen_sock);
    return 0;
}
