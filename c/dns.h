#include <stdint.h>
#ifndef DNS_H
#define DNS_H
struct msg_header{
    uint16_t id;
    /*flags*/
    uint16_t flags;
    /*number of entries in the question section*/
    uint16_t qdcount;
    /*number of resource records in answer section*/
    uint16_t ancount;
    /*number of name server resource in authority record section*/
    uint16_t nscount;
    /*number of resource records in additional section*/
    uint16_t arcount;
};
struct dns_rr{
    char *name;
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t rdlength;
    void *rdata;
    struct dns_rr *next;
};

struct mx_rdata{
    uint16_t preference;
    char *domain;
};
struct dns_msg{
    struct msg_header *hdr;
    char *buf; //pointer the raw message
    int msg_len;
    int hdr_len;
    int qd_len;
    int an_len;
    int ns_len;
    int ar_len;
    struct dns_rr *qd;
    struct dns_rr *an;
    struct dns_rr *ns;
    struct dns_rr *ar;
};
void free_rr(struct dns_rr *rr);

void free_dns_msg(struct dns_msg *m);

void dump_header(char *buf);
size_t set_qname(char *dest, char *dname);
size_t parse_rr(char *start,size_t offset, size_t ncount, struct dns_rr **res);
size_t parse_rname(char *start,size_t offset,char **res);

int parse_msg(struct dns_msg *m);
void print_rr(struct dns_rr *rr);
int bind_request(char *domain,uint16_t qtype,char **res);
/*
inline uint8_t get_rcode(uint16_t flags){
    uint8_t *u;
    u=(uint8_t*)&flags;
    u++;
    return (*u & 0x0f);
}
inline uint8_t get_qr(uint16_t flags){
    uint8_t *u;
    u=(uint8_t*)&flags;
    return ((*u >> 7) & 0x01);
}
inline uint8_t get_opcode(uint16_t flags){
    uint8_t *u;
    uint8_t u1;
    u=(uint8_t*)&flags;
    u1=(*u >> 3) & 0x0f;
    return u1;
}
inline uint8_t get_aa(uint16_t flags){
    uint8_t *u;
    u=(uint8_t*)&flags;
    return ((*u >> 2) & 0x01);
}
inline uint8_t get_tc(uint16_t flags){
    uint8_t *u;
    u=(uint8_t*)&flags;
    return ((*u >> 1) & 0x01);
}
inline uint8_t get_rd(uint16_t flags){
    uint8_t *u;
    u=(uint8_t*)&flags;
    return (*u & 0x01);
}
inline uint8_t get_ra(uint16_t flags){
    uint8_t *u;
    u=(uint8_t*)&flags;
    u++;
    return ((*u >> 7) & 0x01);
}
*/
/* OPCODE */
#define QUERY 0
#define IQUERY 1
#define STATUS 2
#define ASSIGN 3
#define NOTIFY 4
#define UPDATE 5

/* RCODE */

/* NoError*/
#define NOERR 0
/*Form error*/
#define FORMATERR 1
/*Serve Fail*/
#define SERVFAIL 2
/*name error*/
#define NXDOMAIN 3
/*Not Implemented*/
#define NOIMP 4
/*refused*/
#define REFUSED 5
/*Name exists when it should not*/
#define YXDOMAIN 6
/* RR set exists when it should not*/
#define YXRRSET 7
/*rr set that should exists does not*/
#define NXRRSET 8
/*server not authoritative for zone*/
#define NOTAUTH 9
/*name not contained in zone*/
#define NOTZONE 10
/*bad opt version*/
#define BADVERS 16
/*tsig signature failure*/
#define BADSIG 16
/*key not recognized*/
#define BADKEY 17
/*signature out of time window*/
#define BADTIME 18
/*bad tkey mode*/
#define BADMODE 19
/*duplicate key name*/
#define BADNAME 20
/*algorithm not supported*/
#define BADALG 21


/*RR type */
#define RR_A 1
#define RR_NS 2
/*mail destination*/
#define RR_MD 3
#define RR_MF 4
#define RR_CNAME 5
/*marks the start of a zone authority*/
#define RR_SOA 6
/*mailbox domain name*/
#define RR_MB 7
/*mail group member*/
#define RR_MG 8
/*mail rename domain name*/
#define RR_MR 9
/*null RR*/
#define RR_NULL 10
/*well known service description*/
#define RR_WKS 11
/*domain name pointer*/
#define RR_PTR 12
/*host information*/
#define RR_HINFO 13
/*mailbox or mail list information*/
#define RR_MINFO 14
/*mail exchange*/
#define RR_MX 15
/*text strings*/
#define RR_TXT 16
#define RR_AAAA 28

/* class values*/
/* internet*/
#define CLS_IN 1
/*CSNET*/
#define CLS_CS 2
/*CHAOS*/
#define CLS_CH 3
/*hesiod*/
#define CLS_HS 4


#endif
