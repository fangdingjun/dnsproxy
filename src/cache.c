#include <stdio.h>
#include <sqlite3.h>
#include "dns.h"
#include "dnsproxy.h"
#include "cache.h"

int is_exists(sqlite3 *db, char *tbl_name, char *name, int type, char *rdata);

sqlite3 *open_db(char *filename)
{
    int rc;
    sqlite3 *db;
    rc = sqlite3_open(filename, &db);
    if (rc != SQLITE_OK) {
        if (db) {
            ERR("open db %s failed: %s\n", filename, sqlite3_errmsg(db));
            sqlite3_close(db);
        } else {
            ERR("open db %s failed: %s\n", filename, sqlite3_errmsg(db));
        }
        return NULL;
    }
    return db;
}

int init_cache(sqlite3 * db, size_t size)
{
    sqlite3_stmt *stmt;
    char sql[100];
    size_t page_size = 0;
    int rc;
    size_t page_count;
    sprintf(sql, "PRAGMA page_size");
    rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ERR("parse sql failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    while (1) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_BUSY)
            continue;

        if (rc != SQLITE_ROW)
            break;

        page_size = sqlite3_column_int(stmt, 0);

    }

    if (rc != SQLITE_DONE) {
        ERR("get page size failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    if (page_size == 0) {
        ERR("get page size faild\n");
        return -1;
    }
    DBG("get page size: %d\n", page_size);
    page_count = size / page_size;
    DBG("set max page count: %d\n", page_count);
    sprintf(sql, "PRAGMA max_page_count = %d", page_count);
    rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ERR("parse sql failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    while (1) {
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_BUSY && rc != SQLITE_ROW)
            break;
    }
    if (rc != SQLITE_DONE) {
        ERR("execute sql error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int create_cache_table(sqlite3 * db, char *tbl_name)
{
    sqlite3_stmt *stmt;
    int rc;
    char sql[256];
    sprintf(sql, "create table %s ("
            "id integer primary key autoincrement,"
            "domain varchar(100),"
            "rrtype int,"
            "clstype int," "rrdata text," "expired long" ")", tbl_name);
    rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ERR("parse create table sql failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    while (1) {
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_BUSY && rc != SQLITE_ROW)
            break;
    }
    if (rc != SQLITE_DONE) {
        ERR("create table failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int cache_store(sqlite3 * db, char *tbl_name, struct dns_rr *r)
{
    struct dns_rr *r1;
    char sql[1024];
    time_t now;
    sqlite3_stmt *stmt;
    int rc;

    long expired;
    
    if ( r == NULL) return -1;
    
    now = time(NULL);
    sprintf(sql,
            "insert into %s (domain, rrtype, clstype, rrdata, expired)"
            " values(?, ?, ?, ?, ?)", tbl_name);

    rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ERR("parse sql error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    

    for (r1 = r; r1 != NULL; r1 = r1->next) {

        if (r1->type != RR_A && r1->type != RR_AAAA
            && r1->type != RR_CNAME)
            continue;
        
        /* check if exists on cache */
        if (is_exists(db, tbl_name, r1->name, r1->type, (char *)r1->rdata) > 0){
            DBG("cache: %s IN 0x%02x %s is exists, skip store it\n", 
                r1->name, r1->type, (char *)r1->rdata);
            continue;
        }
        
        expired = now + r1->ttl + 600;
        
        DBG("cache store: %s IN 0x%02x %s, expired in %ld\n",
            r1->name, r1->type, (char *)r1->rdata, expired);
        
        //sqlite3_bind_text(stmt, 1, tbl_name, strlen(tbl_name) + 1,
        //                 SQLITE_STATIC);
        rc = sqlite3_bind_text(stmt, 1, r1->name, strlen(r1->name),
                               SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            ERR("bind domain: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }
        
        rc = sqlite3_bind_int(stmt, 2, r1->type);
        if (rc != SQLITE_OK) {
            ERR("bind type: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }
        
        rc = sqlite3_bind_int(stmt, 3, r1->cls);
        if (rc != SQLITE_OK) {
            ERR("bind cls: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }
        
        rc = sqlite3_bind_text(stmt, 4, r1->rdata, strlen(r1->rdata),
                               SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            ERR("bind rdata: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }
        
        rc = sqlite3_bind_int(stmt, 5, expired);
        if (rc != SQLITE_OK) {
            ERR("bind expired: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }

        while (1) {
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_BUSY && rc != SQLITE_ROW)
                break;
        }

        if (rc != SQLITE_DONE) {
            ERR("insert to table failed: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    sqlite3_finalize(stmt);
    return 0;

}

struct dns_rr *cache_fetch(sqlite3 * db, char *tbl_name, char *qname,
                           int qtype)
{
    sqlite3_stmt *stmt;
    char sql[1024];
    int rc;
    time_t now;
    struct dns_rr *r;
    struct dns_rr *r1;
    char *domain;
    char *rdata;
    int rtype, clstype;
    int ttl;
    char *q;

    int len;
    int count;

    int i;
    int t = RR_CNAME;

    int has_a = 0;
    
    if ( qname == NULL || db == NULL || tbl_name == NULL) return NULL;
    
    r = NULL;
    r1 = NULL;
    q = qname;
    now = time(NULL);
    sprintf(sql,
            "select domain, rrtype, clstype, rrdata, expired from %s where domain = ? and rrtype = ? and expired > %ld",
            tbl_name, now);
    rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ERR("parse sql failed: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    //int i = 0;

    for (i = 0; ; i++) {
        count = 0;
        //DBG("bind to |%s|\n", q);
        
        rc = sqlite3_bind_text(stmt, 1, q, strlen(q), SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            ERR("bind domain failed: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return NULL;
        }
        
        rc = sqlite3_bind_int(stmt, 2, t);
        if (rc != SQLITE_OK) {
            ERR("bind rtype failed: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return NULL;
        }

        while (1) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_BUSY)
                continue;
            if (rc != SQLITE_ROW) {
                break;
            }
            count++;
            if (r == NULL) {
                r = r1 = malloc(sizeof(struct dns_rr));
                if (r == NULL) {
                    ERR("out of memory\n");
                    goto done;
                }
                memset(r, 0, sizeof(struct dns_rr));
            } else {
                r1->next = malloc(sizeof(struct dns_rr));
                r1 = r1->next;
                if (r1 == NULL) {
                    ERR("out of memory\n");
                    free_rr(r);
                    r = NULL;
                    goto done;
                }
                memset(r1, 0, sizeof(struct dns_rr));
            }
            domain = sqlite3_column_text(stmt, 0);
            len = sqlite3_column_bytes(stmt, 0);
            r1->name = malloc(len + 1);
            if (r1->name == NULL) {
                ERR("out of memory\n");
                free_rr(r);
                r = NULL;
                goto done;
            }
            strcpy(r1->name, domain);
            //DBG("get domain: |%s|\n", r1->name);

            rtype = sqlite3_column_int(stmt, 1);

            r1->type = rtype;
            clstype = sqlite3_column_int(stmt, 2);
            r1->cls = clstype;

            rdata = sqlite3_column_text(stmt, 3);
            len = sqlite3_column_bytes(stmt, 3);
            r1->rdata = malloc(len + 1);
            if (r1->rdata == NULL) {
                ERR("out of memory\n");
                free_rr(r);
                r = NULL;
                goto done;
            }
            strcpy(r1->rdata, rdata);

            ttl = sqlite3_column_int(stmt, 4);
            r1->ttl = ttl - now;

        }
        if (rc != SQLITE_DONE) {
            ERR("query error: %s\n", sqlite3_errmsg(db));
            if (r) free_rr(r);
            r = NULL;
            goto done;
        }
        
        if(r1){
            DBG("cache found: %s IN 0x%02x %s\n", r1->name, r1->type, (char *)r1->rdata);
        }
        
        if (count == 0) {
            if ( t == RR_CNAME){
                /* its CNAME, continue */
                t = qtype;
            }else{
                /* no A or AAAA found, exit */
                break;
            }
        }else{
            if (r1 && r1->type == RR_CNAME){
                /* its CNAME, continue */
                q=r1->rdata;
            }else{
                /* not CNAME, exit */
                break;
            }
        }
        
        DBG("query again\n");
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }
  
    DBG("cache query done\n");
  done:
    sqlite3_finalize(stmt);
        
    if (r){
        /* check if found special type record */
        for( r1=r; r1 != NULL; r1 = r1->next){
            if( r1->type == qtype){
                has_a = 1;
                break;
            }
        }
        
        if (! has_a){
            free_rr(r);
            r = NULL;
            DBG("cache: query type 0x%02x not found, free rr\n", qtype);
        }
    }    

    return r;
}

int delete_expired(sqlite3 * db, char *tbl_name)
{
    sqlite3_stmt *stmt;
    char sql[1024];
    int rc;
    
    time_t now = time(NULL);
    sprintf(sql, "delete from %s where expired <= %ld", tbl_name, now);
    rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ERR("parse sql failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    while(1){
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_BUSY && rc != SQLITE_ROW) break;
    }
    
    if (rc != SQLITE_DONE){
        ERR("delete expired failed: %s\n", sqlite3_errmsg(db));
    }
    
    sqlite3_finalize(stmt);
    return 0;
}


int is_exists(sqlite3 *db, char *tbl_name, char *name, int type, char *rdata){
    sqlite3_stmt *stmt;
    char sql[512];
    int rc;
    int num = 0;
    
    sprintf(sql, "select count(domain) as d from %s where domain = '%s' and  rrtype = %d and expired > %ld",
        tbl_name, name, type, time(NULL));
    
    rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rc != SQLITE_OK){
        ERR("sql error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    while(1){
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_BUSY) continue;
        if (rc != SQLITE_ROW) break;
        num = sqlite3_column_int(stmt, 0);
        //DBG("num = %d\n", num);
    }
    
    if (rc != SQLITE_DONE){
        ERR("sql query failed: %s\n", sqlite3_errmsg(db));
        num = -1;
        goto done;
    }
    if ( num > 0 && num < 10){
        if ( type == RR_A || type == RR_AAAA){
            /* free previous stmt */
            sqlite3_finalize(stmt);
            sprintf(sql, "select count(domain) from %s where domain = '%s' and "
                "rrtype = %d and rrdata = '%s' and expired > %ld",
                tbl_name, name, type, rdata, time(NULL));
            rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
            if (rc != SQLITE_OK){
                ERR("parse sql failed: %s\n", sqlite3_errmsg(db));
                num = 1;
                goto done;
            }
            while(1){
                rc = sqlite3_step(stmt);
                if (rc == SQLITE_BUSY) continue;
                if ( rc != SQLITE_ROW) break;
                num = sqlite3_column_int(stmt, 0);
            }
            if (rc != SQLITE_DONE){
                ERR("sql execute error: %s\n", sqlite3_errmsg(db));
                num =1;
                goto done;
            }
        }
    }
    done:
        sqlite3_finalize(stmt);
        return num;
}
