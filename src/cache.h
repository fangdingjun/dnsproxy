#include <ldns/ldns.h>
#ifndef CACHE_H
#define CACHE_H

#include "dns.h"
#include <sqlite3.h>
extern FILE *logfp;
extern int loglevel;
sqlite3 *open_db(char *filename);
int init_cache(sqlite3 * db, size_t size);
int create_cache_table(sqlite3 * db, char *tbl_name);
int cache_store(sqlite3 * db, char *tbl_name, struct dns_rr *r);
struct dns_rr *cache_fetch(sqlite3 * db, char *tbl_name, char *qname,
                           int qtype);
int delete_expired(sqlite3 * db, char *tbl_name);
int cache_rr(ldns_rr_list * r, sqlite3 * db, char *tblname);
ldns_rr_list *lookup_cache(ldns_rr * q, sqlite3 * db, char *tblname);
sqlite3 *cache_init(char *filename, char *tblname, size_t cache_size);
int delete_expired_rr(sqlite3 * db, char *tblname);
#endif
