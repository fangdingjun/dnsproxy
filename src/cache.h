
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
struct dns_rr *cache_fetch(sqlite3 * db, char *tbl_name, char *qname,int qtype);
int delete_expired(sqlite3 * db, char *tbl_name);
#endif
