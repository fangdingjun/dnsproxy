#include <ldns/ldns.h>
#ifndef CACHE_H
#define CACHE_H

#include <sqlite3.h>
extern FILE *logfp;
extern int loglevel;
int cache_rr(ldns_rr_list * r, sqlite3 * db, char *tblname);
ldns_rr_list *lookup_cache(ldns_rr * q, sqlite3 * db, char *tblname);
sqlite3 *cache_init(char *filename, char *tblname, size_t cache_size);
int delete_expired_rr(sqlite3 * db, const char *tblname);
#endif
