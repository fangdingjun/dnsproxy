/*
#============================================
# Filename:
#    dnsc.c
# Author:
#    fangdingjun@gmail.com
# License:
#   GPLv3 (http://www.gnu.org/licenses/gpl-3.0.html)
# Description:
#   this a dns client program, like dig
# Usage:
#   dnsc [-t type] [-s dnsserver] domain
#============================================
*/


#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <getopt.h>
#include <unistd.h>
//#include "dns.h"
#include <ldns/ldns.h>

int main(int argc, char *argv[])
{
    char *domain;
    char *dnssrv = "8.8.4.4";
    
    struct timeval tv;
    uint16_t q_type = LDNS_RR_TYPE_A;
    int ret = 0;
    int opt;
    ldns_resolver *rlv;
    ldns_rdf *srv_s;
    ldns_pkt *p;
    ldns_rdf *qname;

#ifdef WIN32
    /* initial the win32 sockets */
    WSADATA wsaData;
    WSAStartup(0x2020, &wsaData);
#endif

    /* initial random seed */
    srand(time(NULL));

    while (1) {
        opt = getopt(argc, argv, "t:s:");
        if (opt == -1)
            break;
        switch (opt) {
        case 't':
            if (strcasecmp(optarg, "mx") == 0) {
                q_type = LDNS_RR_TYPE_MX;
            } else if (strcasecmp(optarg, "txt") == 0) {
                q_type = LDNS_RR_TYPE_TXT;
            } else if (strcasecmp(optarg, "a") == 0) {
                q_type = LDNS_RR_TYPE_A;
            } else if (strcasecmp(optarg, "aaaa") == 0) {
                q_type = LDNS_RR_TYPE_AAAA;
            } else if (strcasecmp(optarg, "ns") == 0) {
                q_type = LDNS_RR_TYPE_NS;
            } else {
                printf("unknow type %s\n", optarg);
                ret = -1;
                return ret;
            }
            break;
        case 's':
            dnssrv = optarg;
            break;
        default:
            printf("Usage: %s [-t type] [-s dnsserver] domain\n", argv[0]);
            ret = -1;
            return ret;
        }
    }
    if (optind >= argc) {
        printf("Usage: %s [-t type] [-s dnsserver] domain\n", argv[0]);
        ret = -1;
        return ret;
    }
    domain = argv[optind];

    qname = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, domain);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    srv_s = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A,  dnssrv);

    rlv = ldns_resolver_new();

    ldns_resolver_push_nameserver(rlv, srv_s);

    ldns_resolver_set_retry(rlv, 2);
    ldns_resolver_set_timeout(rlv,tv);
    ldns_resolver_set_retrans(rlv, 1);
    //ldns_resolver_set_recursive(rlv, 1);
    //ldns_resolver_set_debug(rlv, 1);
    ldns_resolver_set_ip6(rlv,1);

    p = ldns_resolver_query(rlv, qname, q_type, LDNS_RR_CLASS_IN, LDNS_RD); 

    ldns_pkt_print(stdout, p);

    ldns_pkt_free(p);
    ldns_rdf_free(qname);
    ldns_rdf_free(srv_s);
    ldns_resolver_free(rlv);

    ret = 0;

    return ret;
}
