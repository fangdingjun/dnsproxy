#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <unistd.h>
#include "dns.h"

int main(int argc, char *argv[])
{
    //char buf[512];
    // char *domain="www.tianya.cn";
    char *domain;
    //struct msg_header *p;
    char *dnssrv = "8.8.4.4";
    //char *dnssrv="114.114.114.114";
    //int n;
    fd_set rds;
    //int retval;
    struct timeval tv;
    int msg_len = 0;
    //char *p1,*p2;
    char rcvbuf[512];
    uint16_t q_type = RR_A;
    //uint16_t r_type,r_class;
    char *msg;
    //uint16_t i;
    //int i;
    int sock;
    int retry_times = 0;
    int ret = 0;
    struct sockaddr_in srvaddr;
    int opt;
    //printf("argc %d\n",argc);
    while (1) {
        opt = getopt(argc, argv, "t:s:");
        if (opt == -1)
            break;
        switch (opt) {
        case 't':
            if (strcasecmp(optarg, "mx") == 0) {
                q_type = RR_MX;
            } else if (strcasecmp(optarg, "txt") == 0) {
                q_type = RR_TXT;
            } else if (strcasecmp(optarg, "a") == 0) {
                q_type = RR_A;
            } else if (strcasecmp(optarg, "aaaa") == 0) {
                q_type = RR_AAAA;
            } else if (strcasecmp(optarg, "ns") == 0) {
                q_type = RR_NS;
            } else {
                printf("unknow type %s\n", optarg);
                ret = -1;
                goto err1;
            }
            break;
        case 's':
            dnssrv = optarg;
            break;
        default:
            printf("Usage: %s [-t type] [-s dnsserver] domain\n", argv[0]);
            ret = -1;
            goto err1;
        }
    }
    if (optind >= argc) {
        printf("Usage: %s [-t type] [-s dnsserver] domain\n", argv[0]);
        ret = -1;
        goto err1;
    }
    domain = argv[optind];
    msg_len = bind_request(domain, q_type, &msg);
    //dump_header(msg);

    memset(&srvaddr, 0, sizeof(srvaddr));
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket()");
        ret = -1;
        goto err2;
    }
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_port = htons(53);
    srvaddr.sin_addr.s_addr = inet_addr(dnssrv);
    retry_times = 0;
  retry:
    ret =
        sendto(sock, msg, msg_len, 0, (struct sockaddr *) &srvaddr,
               sizeof(srvaddr));
    if (ret < 0) {
        perror("sendto()");
        ret = -1;
        goto err3;
    }

    FD_ZERO(&rds);
    FD_SET(sock, &rds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    ret = select(sock + 1, &rds, NULL, NULL, &tv);
    if (ret < 0) {
        perror("select()");
        ret = -1;
        goto err3;
    } else if (ret == 0) {
        retry_times++;
        if (retry_times < 3) {
            printf("timeout, retrying...\n");
            goto retry;
        } else {
            goto err3;
        }
    }
    ret = recvfrom(sock, rcvbuf, 512, 0, NULL, NULL);
    if (ret < 0) {
        perror("recvfrom()");
        ret = -1;
        goto err3;
    }
    //dump_header(rcvbuf);
    struct dns_msg *rmsg;
    rmsg = malloc(sizeof(struct dns_msg));
    memset(rmsg, 0, sizeof(struct dns_msg));
    rmsg->msg_len = ret;
    rmsg->buf = malloc(rmsg->msg_len);
    memcpy(rmsg->buf, rcvbuf, rmsg->msg_len);
    parse_msg(rmsg);
    //print_rr(rmsg->qd);
    print_rr(rmsg->an);
    print_rr(rmsg->ns);
    print_rr(rmsg->ar);
    free_dns_msg(rmsg);
  err3:
    close(sock);
  err2:
    if (msg)
        free(msg);
  err1:
    return ret;
}
