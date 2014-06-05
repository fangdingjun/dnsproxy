#include <stdio.h>
#include <sqlite3.h>
#include "dns.h"
#include "dnsproxy.h"
#include "cache.h"


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
    now = time(NULL);
    long expired;
    sprintf(sql,
            "insert into %s (domain, rrtype, clstype, rrdata, expired)"
            " values(?, ?, ?, ?, ?)", tbl_name);

    rc = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        ERR("parse sql error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    expired = now + r->ttl;

    for (r1 = r; r1 != NULL; r1 = r1->next) {

        if (r1->type != RR_A && r1->type != RR_AAAA
            && r1->type != RR_CNAME)
            continue;

        //sqlite3_bind_text(stmt, 1, tbl_name, strlen(tbl_name) + 1,
        //                 SQLITE_STATIC);
        rc = sqlite3_bind_text(stmt, 1, r1->name, strlen(r1->name) + 1,
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
        rc = sqlite3_bind_text(stmt, 4, r1->rdata, strlen(r1->rdata) + 1,
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
    int len;
    int count;

    int i;
    int t = RR_CNAME;
    for (i = 0; i < 2; i++) {
        count = 0;
        //DBG("bind to |%s|\n", q);
        rc = sqlite3_bind_text(stmt, 1, q, strlen(q) + 1, SQLITE_STATIC);
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
            goto done;
        }
        if (count && i == 0) {
            q = r1->name;
            DBG("found CNAME %s\n", q);
        }
        t = qtype;
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }
  done:
    sqlite3_finalize(stmt);

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
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return 0;
}
