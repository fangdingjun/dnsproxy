
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
//#include <sys/time.h>
//#include <sys/select.h>
//#include <getopt.h>
#include "dns.h"

void free_dns_msg(struct dns_msg *m)
{
    if (m) {
        if (m->buf)
            free(m->buf);
        if (m->qd)
            free_rr(m->qd);
        if (m->an)
            free_rr(m->an);
        if (m->ns)
            free_rr(m->ns);
        if (m->ar)
            free_rr(m->ar);
        free(m);
    }
}

size_t set_qname(char *p, char *name)
{
    char *p1, *p2, *p3;
    size_t n;
    if (p == NULL || name == NULL)
        return 0;

    p3 = p;
    p1 = name;
    p2 = strchr(name, '.');
    while (p2) {                // "." is exists in domain name
        n = p2 - p1;
        *p3 = n;
        p3++;
        // copy to dest
        strncpy(p3, p1, n);
        p3 += n;
        p2++;
        p1 = p2;
        p2 = strchr(p1, '.');
    }
    // '.' is not in string or in the last section
    p2 = strchr(p1, '\0');
    n = p2 - p1;
    *p3 = n;
    p3++;

    // copy to dest
    strncpy(p3, p1, n);
    p3 += n;
    *p3 = '\0';
    p3++;
    // the total length
    return (p3 - p);
}

/*
 * convert domain label to domain name string
 * argv 1: the start of the dns resonse message buffer
 * argv 2: the offset of the rname
 * argv 3: the length to return
 * return the domain name string
 */
size_t parse_rname(char *start, size_t offset, char **res)
{
    uint8_t nn;
    char *p1;
    uint16_t poffset;
    char buf[1024];
    int has_pointer = 0;
    size_t l = 0;
    buf[0] = '\0';

    /*check argument */
    if (start == NULL) {
        l = 0;
        return l;
    }
    p1 = start + offset;
    nn = *p1;
    while (nn) {
        //printf("nn=%02x\n",nn);
        /* this is a pointer */
        if (nn & (0x3 << 6)) {
            //printf("found 0xc0\n");
            /*get the offset */
            poffset = *((uint16_t *) p1);

            /*convert to host byte order */
            poffset = ntohs(poffset);

            /*clear the start two bits */
            poffset &= (~(0x3 << 14));
            //printf("poffset %02x\n",poffset);
            if (l == 0) {
                l = p1 - (start + offset) + 2;
            }
            has_pointer = 1;
            p1 = start + poffset;
            nn = *p1;
        }
        //printf("nn=%02x\n",nn);
        p1++;
        strncat(buf, p1, nn);
        p1 += nn;
        nn = *p1;
        strcat(buf, ".");
    }
    if (!has_pointer) {
        l = p1 - (start + offset) + 1;
    }
    *res = strdup(buf);
    //printf("%s %s\n",__FUNCTION__,buf);
    return l;
}

/*
 * parse the dns resource record
 * argv 1: the start of dns message buffer
 * argv 2: the offset to start of rr
 * argv 3: the number of rr to parse
 * return a pointer to the list of struct dns_rr
 *    note:
 *       you must free the dns_rr->name and dns_rr->rdata 
 *         before you free the dns_rr struct 
 */
size_t parse_rr(char *start, size_t offset, size_t ncount,
                struct dns_rr ** res)
{
    size_t rname_len = 0;
    size_t rr_len = 0;
    char *p;
    struct dns_rr *rr_head = NULL, *rr_cur = NULL;
    int i;
    p = start + offset;
    for (i = 0; i < ncount; i++) {
        if (i == 0) {
            rr_head = (struct dns_rr *) malloc(sizeof(struct dns_rr));
            memset(rr_head, 0, sizeof(struct dns_rr));
            rr_cur = rr_head;
        } else {
            rr_cur->next = (struct dns_rr *) malloc(sizeof(struct dns_rr));
            rr_cur = rr_cur->next;
            memset(rr_cur, 0, sizeof(struct dns_rr));
        }
        rname_len = parse_rname(start, p - start, &(rr_cur->name));
        p += rname_len;
        rr_cur->type = ntohs(*(uint16_t *) p);
        p += 2;
        rr_cur->cls = ntohs(*(uint16_t *) p);
        p += 2;
        rr_cur->ttl = ntohl(*(uint32_t *) p);
        p += 4;
        rr_cur->rdlength = ntohs(*(uint16_t *) p);
        p += 2;
        if (rr_cur->type == RR_CNAME) {
            parse_rname(start, p - start, (char **) &(rr_cur->rdata));
        } else if (rr_cur->type == RR_A) {
            char d[20];
            if (inet_ntop(AF_INET, (void *) p, d, 20)) {
                rr_cur->rdata = strdup(d);
            } else {
                perror("inet_ntop");
                rr_cur->rdata = NULL;
            }
            //rr_cur->rdata=strdup(inet_ntoa(*(struct in_addr*)p));
        } else if (rr_cur->type == RR_NS) {
            parse_rname(start, p - start, (char **) &(rr_cur->rdata));
        } else if (rr_cur->type == RR_AAAA) {
            char dst[64];
            if (inet_ntop(AF_INET6, (void *) p, dst, 64)) {
                rr_cur->rdata = strdup(dst);
            } else {
                perror("inet_ntop");
                rr_cur->rdata = NULL;
            }
        } else if (rr_cur->type == RR_MX) {
            struct mx_rdata *mx;
            mx = malloc(sizeof(struct mx_rdata));
            mx->preference = ntohs(*((uint16_t *) p));
            //printf("mx preference=%02x\n",mx->preference);
            parse_rname(start, p - start + 2, &(mx->domain));
            //printf("mx domain: %s\n",mx->domain);
            rr_cur->rdata = mx;
        } else if (rr_cur->type == RR_TXT) {
            //rr_cur->rdata=parse_rname(start,p-start,NULL,rr_cur->rdlength);
            rr_cur->rdata = malloc(rr_cur->rdlength);
            memcpy(rr_cur->rdata, p, rr_cur->rdlength);

        } else {
            rr_cur->rdata = malloc(rr_cur->rdlength);
            memcpy(rr_cur->rdata, p, rr_cur->rdlength);
        }
        p += rr_cur->rdlength;
        //printf("%s name: %s, type: %u, class: %u\n",
        //       __FUNCTION__,rr_cur->name,rr_cur->type,rr_cur->cls);
    }
    rr_len = p - (start + offset);
    *res = rr_head;
    return rr_len;
}

void dump_header(char *p)
{
    uint16_t n;
    printf("id: %u", ntohs(*((uint16_t *) p)));
    printf(", qr: %u", ((*(p + 2)) >> 7) & 0x1);
    printf(", opcode: %u", (((*(p + 2)) << 1) >> 4) & 0x0f);
    printf(", aa: %u", ((*(p + 2)) >> 2) & 0x1);
    printf(", tc: %u", ((*(p + 2)) >> 1) & 0x1);
    printf(", rd: %u", (*(p + 2)) & 0x1);
    printf(", ra: %u", ((*(p + 3)) >> 7) & 0x1);
    printf(", rcode: %u", (*(p + 3)) & 0x0f);
    n = ((struct msg_header *) p)->qdcount;
    printf(", qdcount: %u", ntohs(n));
    n = ((struct msg_header *) p)->ancount;
    printf(", ancount: %u", ntohs(n));

    n = ((struct msg_header *) p)->nscount;
    printf(", nscount: %u", ntohs(n));
    n = ((struct msg_header *) p)->arcount;
    printf(", arcount: %u", ntohs(n));
    printf("\n");
}

void print_rr(struct dns_rr *rr)
{
    struct dns_rr *h;
    uint16_t pre;
    char *dom;
    if (rr == NULL)
        return;

    for (h = rr; h; h = h->next) {
        printf("%-25s", h->name);
        printf(" %-5u", h->ttl);
        if (h->cls == 1) {
            printf(" IN");
        } else {
            printf(" *");
        }
        switch (h->type) {
        case RR_A:
            printf(" A %-20s", (char *) h->rdata);
            break;
        case RR_CNAME:
            printf(" CNAME %-20s", (char *) h->rdata);
            break;
        case RR_AAAA:
            printf(" AAAA %-20s", (char *) h->rdata);
            break;
        case RR_NS:
            printf(" NS %-20s", (char *) h->rdata);
            break;
        case RR_MX:
            pre = ((struct mx_rdata *) h->rdata)->preference;
            dom = ((struct mx_rdata *) h->rdata)->domain;
            printf(" MX %u %-20s", pre, dom);
            break;
        case RR_TXT:
            printf(" TXT \"%s\"", (char *) h->rdata);
            break;
        default:
            printf(", unknown");
            break;
        }
        printf("\n");
    }
}

void free_rr(struct dns_rr *rr)
{
    struct dns_rr *tmp, *tmp1;
    if (rr == NULL)
        return;
    for (tmp = rr; tmp; tmp = tmp->next) {
        tmp1 = tmp;
        if (tmp1->name)
            free(tmp1->name);
        if (tmp1->rdata) {
            if (tmp1->type == RR_MX) {
                char *t;
                t = ((struct mx_rdata *) tmp1->rdata)->domain;
                if (t)
                    free(t);
            }
            free(tmp1->rdata);
        }
        free(tmp1);
    }
}

/*
 * bind a dns request message
 * argv 1: domain name
 * argv 2: request type, RR_A,RR_AAAA,RR_MX or RR_TXT
 * the pointer to store result
 * return message length
 */
int bind_request(char *domain, uint16_t qtype, char **res)
{
    struct msg_header *hdr;
    char buf[512];
    char *p1;
    int nlen = 0;
    int hdr_len;
    if (!domain)
        return 0;
    memset(buf, 0, sizeof(buf));
    hdr = (struct msg_header *) buf;
    hdr->id = getpid();
    *((uint8_t *) & hdr->flags) |= 0x1; // set rd
    hdr->qdcount = htons(0x1);  // set QDCOUNT
    p1 = buf + sizeof(struct msg_header);
    nlen = set_qname(p1, domain);
    p1 += nlen;
    *(uint16_t *) p1 = htons(qtype);    // set QTYPE
    p1 += 2;
    *(uint16_t *) p1 = htons(0x1);  // set QCLASS
    p1 += 2;
    hdr_len = p1 - buf;
    *res = malloc(hdr_len);
    memcpy(*res, buf, hdr_len);
    return hdr_len;
}

size_t parse_qd(char *start, size_t offset, struct dns_rr ** res)
{
    char *p1;
    struct dns_rr *r;
    size_t len;
    p1 = start + offset;
    r = malloc(sizeof(struct dns_rr));
    memset(r, 0, sizeof(struct dns_rr));
    len = parse_rname(start, offset, &r->name);
    p1 += len;
    r->type = ntohs(*(uint16_t *) p1);
    p1 += 2;
    r->cls = ntohs(*(uint16_t *) p1);
    p1 += 2;
    *res = r;
    return (p1 - (start + offset));
}

int parse_msg(struct dns_msg *m)
{
    char *p1;
    //uint16_t flags;
    uint16_t l;
    size_t offset = 0;
    p1 = m->buf;
    m->hdr = (struct msg_header *) m->buf;
    //flags=m->hdr->flags;
    offset = sizeof(struct msg_header);
    l = ntohs(m->hdr->qdcount);
    if (l) {
        m->qd_len = parse_qd(p1, offset, &(m->qd));
        offset += m->qd_len;
        //printf("qd qd_len %02x %s type: %02x, class: %02x\n",
        //       m->qd_len,m->qd->name,m->qd->type,m->qd->cls);
    }
    l = ntohs(m->hdr->ancount);
    if (l) {
        m->an_len = parse_rr(p1, offset, l, &(m->an));
        offset += m->an_len;
        /*
           printf("an %s type: %02x, class: %02x\n",
           m->an->name,m->an->type,m->an->cls);
         */
    }
    l = ntohs(m->hdr->nscount);
    if (l) {
        m->ns_len = parse_rr(p1, offset, l, &m->ns);
        offset += m->ns_len;
        /*
           printf("ns %s type: %02x, class: %02x\n",
           m->ns->name,m->ns->type,m->ns->cls);
         */
    }
    l = ntohs(m->hdr->arcount);
    if (l) {
        m->ar_len = parse_rr(p1, offset, l, &m->ar);
        offset += m->ar_len;
        /* printf("ar %s type: %02x, class: %02x\n",
           m->ar->name,m->ar->type,m->ar->cls);
         */
    }
    //printf("end\n");
    return 0;
}
