
#include "dns.h"
#include "dnsproxy.h"

#define MAX_QUEUE 100


char *default_servers[] = {
    "8.8.8.8",
    "114.114.114.114",
    "208.67.222.222",
    "1.2.4.8",
    NULL
};

//int log(int level, char *fmt, args...);
char *listen_ip = "127.0.0.1";

int listen_port = 53;
FILE *logfp=NULL;

char **servers = default_servers;
int become_daemon = 0;

char *logfile="dnsproxy.log";

int loglevel = 3;

/* the ip lists that china GFW used for DNS cache pollution 
*  http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93
*/
char *blacklist = "iplist.txt";
char *black_ips = NULL;

struct arg_map arguments[]={
    {"listen_ip", ARG_STRING, (void**)&listen_ip},
    {"listen_port",ARG_INT, (void**)&listen_port},
    {"servers",ARG_STR_ARRARY,(void**)&servers},
    {"daemon",ARG_INT,(void**)&become_daemon},
    {"blacklist",ARG_STRING,(void**)&blacklist},
    {"logfile",ARG_STRING,(void **)&logfile},
    {"loglevel",ARG_INT,(void **)&loglevel},
    {NULL,0,NULL}
};

#ifdef USE_EPOLL
int epfd;
struct epoll_event events[MAX_QUEUE + 1];
#endif

struct msg_data msg[MAX_QUEUE + 1];


int recv_from_client(struct msg_data *d)
{
    socklen_t l;
    l = sizeof(struct sockaddr_in);
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
    DBG("recv %d bytes from %s:%d\n", d->msg_len,
           inet_ntoa(d->client_addr.sin_addr),
           ntohs(d->client_addr.sin_port));
    send_to_server(d);
    return 0;
}

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
    for (i = 0;; i++) {
        if (servers[i] == NULL) {
            break;
        }

        saddr.sin_addr.s_addr = inet_addr(servers[i]);

        if (sendto
            (d->srv_fd, d->msg_buf, d->msg_len, 0,
             (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
#ifdef WIN32
            perror("sendto server");
#else
            ERR("sendto server failed: %s\n", strerror(errno));
#endif
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
        ERR("add srv_fd failed: %s\n", strerror(errno));
        close(d->srv_fd);
        memset(d, 0, sizeof(struct msg_data));
        return -1;
    }
#endif
    d->last_active = time(NULL);
    DBG("send to server success\n");
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
        if(!black_ips) break;

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
                ip_found = strstr(black_ips, ip);
                if (ip_found != NULL) { /* ip is in blacklist */
                    found = 1;
                    WARN("found bad ip %s, continue.\n", ip);
                    break;
                }
            }
        }
        free_dns_msg(m);

        if (found) {
            return -1;
        }
    } while (0);
    DBG("recv %d bytes from server\n", msg_len);
    send_to_client(d, buf, msg_len);
    return 0;
}

int send_to_client(struct msg_data *d, char *msg, int msg_len)
{

    if (sendto
        (d->listen_fd, msg, msg_len, 0,
         (struct sockaddr *) &d->client_addr,
         sizeof(struct sockaddr_in)) < 0) {
#ifdef WIN32
        perror("send to client");
#else
        ERR("send to client failed: %s\n", strerror(errno));
#endif
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
    DBG("send to %s:%d\n", inet_ntoa(d->client_addr.sin_addr),
           htons(d->client_addr.sin_port));
    close(d->srv_fd);
    memset(d, 0, sizeof(struct msg_data));

    return 0;
}

int main(int argc, char *argv[])
{
    int listen_fd;
    int i;
    int j;
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
    int child = 0;
    for(i=1; i<argc; i++){
        if(strcmp(argv[i], "child") == 0){
            child = 1;
        }
    }
#endif 
    parse_cfg("dnsproxy.cfg", arguments);
    if(blacklist){
        get_blackip(blacklist, &black_ips);
    }

    if(logfile){
        if(strcmp(logfile,"stdout")==0 || strcmp(logfile,"stderr") == 0){
            logfp=stdout;
        }else{
            logfp = fopen(logfile, "a");
            if(logfp == NULL){
                //perror(logfile);
                fprintf(stderr,"open %s failed\n", logfile);
            }
        }
    }
    if (become_daemon){
#ifdef WIN32
        if(child == 0){
            char buf[1024];
            STARTUPINFO si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si));
            si.cb=sizeof(si);
            ZeroMemory(&pi, sizeof(pi));
            strcpy(buf, argv[0]);
            for(i=1;i<argc;i++){
                strcat(buf, " ");
                strcat(buf,argv[i]);
            }
            strcat(buf," child");
            if(!CreateProcess(NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)){
                fprintf(stderr,"create process failed\n");
                exit(-1);
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            exit(0);
        }
#else
        daemon(1,1);
#endif
        freopen(NULLDEV, "w", stdout);
        freopen(NULLDEV, "w", stderr);
    }
#ifdef WIN32
    /* initial the win32 sockets */
    WSADATA wsaData;
    WSAStartup(0x2020, &wsaData);
#endif

    memset(msg, 0, sizeof(msg));
#ifdef USE_EPOLL
    epfd = epoll_create(MAX_QUEUE);

    if (epfd < 0) {
        ERR("epoll_create failed: %s\n", strerror(errno));
        exit(-1);
    }
#endif
    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd < 0) {
#ifdef WIN32
        perror("create listen socket");
#else
        ERR("create listen socket failed: %s\n", strerror(errno));
#endif
        exit(-1);
    }
    
#ifdef WIN32
    {
        /* avoid errno 10054 on udp socket */
        int reported = 0;
        DWORD ret = 0;
        int status = WSAIoctl(listen_fd, SIO_UDP_CONNRESET, &reported,
            sizeof(reported), NULL, 0, &ret, NULL, NULL);
        if (status == SOCKET_ERROR){
            perror("SIO_UDP_CONNRESET");
            exit(-1);
        }
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
            ERR("epoll_wait failed: %s\n", strerror(errno));
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


