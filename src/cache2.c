#include <stdio.h>
#if WIN32
#include <ws2tcpip.h>           /* for socklen_t  on ldns.h */
#endif
#include <sqlite3.h>
#include <ldns/ldns.h>
#include "dns.h"
#include "dnsproxy.h"

extern int loglevel;
extern FILE *logfp;
static int create_dnscache_table(sqlite3 * db, const char *tblname);
static int cache_rr_a_aaaa(const ldns_rr_list * r, sqlite3 * db,
                           const char *tblname);
static int cache_rr_cname(const ldns_rr_list * r, sqlite3 * db,
                          const char *tblname);
ldns_rr_list *lookup_cache(const ldns_rr * q, sqlite3 * db,
                           const char *tblname);
static int lookup_cache_by_type(ldns_rdf * owner, int type,
                                ldns_rr_list * ret, sqlite3 * db,
                                const char *tblname);
static int lookup_cache_by_cname(const ldns_rdf * owner,
                                 ldns_rr_list * ret, sqlite3 * db,
                                 const char *tblname);
static int lookup_cache_by_a_aaaa(ldns_rdf * owner, int type,
                                  ldns_rr_list * ret, sqlite3 * db,
                                  const char *tblname);

#define EXEC_SQL_NO_RESULT(stmt, retvalue, errlabel) do { \
    int rc1 = sqlite3_step(stmt);\
    if ( rc1 == SQLITE_ROW || rc1 == SQLITE_BUSY){\
        continue;\
    }\
    if (rc1 == SQLITE_DONE){\
        break;\
    }\
    ERR("exec sql error: %s\n", sqlite3_errmsg(db));\
    retvalue = -1;\
    goto errlabel;\
} while(1)

#define EXEC_SQL_BEGIN(stmt, retvalue, errlabel) do {\
    int rc1 = sqlite3_step(stmt);\
    if ( rc1 == SQLITE_BUSY){\
        continue;\
    }\
    if (rc1 == SQLITE_DONE){\
        break;\
    }\
    if (rc1 != SQLITE_ROW){\
        ERR("exec sql error: %s\n", sqlite3_errmsg(db));\
        retvalue = -1;\
        goto errlabel;\
    }

#define EXEC_SQL_END  }while(1)

#define PREPARE_SQL(db, sql, len, stmt, retvalue, errlabel) do{\
    int rc1=sqlite3_prepare(db, sql, len, &stmt, NULL);\
    if (rc1 != SQLITE_OK){\
        ERR("pare sql failed: %s\n", sqlite3_errmsg(db));\
        retvalue = -1;\
        goto errlabel;\
    }\
}while(0)

/* set max memory size and create the table */
sqlite3 *cache_init(const char *filename, const char *tblname,
                    size_t cache_size)
{

    sqlite3 *db = NULL;
    sqlite3_stmt *stmt;
    int ret;
    char sql[100] = "PRAGMA page_size";
    size_t page_size = 0;
    size_t page_total;

    DBG("set max cache size %d\n", cache_size);
    if (sqlite3_open(filename, &db) != SQLITE_OK) {
        if (db) {
            sqlite3_close(db);
            db = NULL;
        }
        ERR("open db %s failed\n", filename);
        goto err1;
    }

    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);

    EXEC_SQL_BEGIN(stmt, ret, err2);
    page_size = sqlite3_column_int(stmt, 0);
    EXEC_SQL_END;

    DBG("get page_size %d\n", page_size);
    sqlite3_finalize(stmt);

    /* cache size must greater than 1MB */
    if (cache_size < 1 * 1024 * 1024) {
        cache_size = 1 * 1024 * 1024;
    }

    /* fallback to 4KB */
    if (page_size == 0) {
        page_size = 4 * 1024;
    }

    page_total = cache_size / page_size;
    DBG("set page count %d\n", page_total);
    sprintf(sql, "PRAGMA max_page_count = %d", page_total);
    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);
    EXEC_SQL_NO_RESULT(stmt, ret, err2);

    /* create table */
    create_dnscache_table(db, tblname);

    /* avoid compiler warnings */
    (void) ret;
  err2:
    sqlite3_finalize(stmt);
  err1:
    return db;
}

static int create_dnscache_table(sqlite3 * db, const char *tblname)
{
    sqlite3_stmt *stmt;
    //int rc;
    int ret = 0;
    char sql[256];
    sprintf(sql,
            "create table %s ("
            "id INTEGER PRIMARY KEY,"
            "owner BLOB,"
            "rr_type INTEGER,"
            "rr_class INTEGER,"
            "rr_data BLOB," "expired INTEGER" ")", tblname);

    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);

    EXEC_SQL_NO_RESULT(stmt, ret, err2);
    DBG("creat table success\n");
  err2:
    sqlite3_finalize(stmt);
  err1:
    return ret;
}

static int cache_exists(const ldns_rr * r, sqlite3 * db,
                        const char *tblname)
{

    char sql[128];
    sqlite3_stmt *stmt;
    int num = 0;
    ldns_rdf *o;
    //int rc;
    int ret = 0;
    int rtype = 0;
    ldns_rr_type t;

    t = ldns_rr_get_type(r);
    switch (t) {
    case LDNS_RR_TYPE_A:
        rtype = LDNS_RR_TYPE_A;
        break;
    case LDNS_RR_TYPE_AAAA:
        rtype = LDNS_RR_TYPE_AAAA;
        break;
    case LDNS_RR_TYPE_CNAME:
        rtype = LDNS_RR_TYPE_CNAME;
        break;
    default:
        break;
    }
    sprintf(sql,
            "select count(owner) from %s where expired > %d and owner = ? and rr_type = ? and rr_class = ?",
            tblname, (int) time(NULL)
        );

    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);

    o = ldns_rr_owner(r);
    /* owner */
    sqlite3_bind_blob(stmt, 1, ldns_rdf_data(o), ldns_rdf_size(o),
                      SQLITE_STATIC);

    /* type */
    sqlite3_bind_int(stmt, 2, rtype);

    /* class */
    sqlite3_bind_int(stmt, 3, LDNS_RR_CLASS_IN);

    EXEC_SQL_BEGIN(stmt, num, err2);

    num = sqlite3_column_int(stmt, 0);

    EXEC_SQL_END;

    (void) ret;

  err2:
    sqlite3_finalize(stmt);
  err1:
    return num;
}

int cache_rr(const ldns_rr_list * r, sqlite3 * db, const char *tblname)
{
    cache_rr_cname(r, db, tblname);
    cache_rr_a_aaaa(r, db, tblname);
    return 0;
}

static int cache_rr_cname(const ldns_rr_list * r, sqlite3 * db,
                          const char *tblname)
{
    ldns_rr *r1;
    ldns_rdf *o;
    ldns_rdf *d;
    size_t rcount;
    int i;
    int t;
    int c;
    uint32_t ttl = 0;
    int rc;
    uint32_t now;
    int ret = 0;
    sqlite3_stmt *stmt;
    //ldns_rr_list *cname = NULL;
    //ldns_rr_a_aaaa *a_aaaa = NULL;

    char sql[512];

    sprintf(sql,
            "insert into %s (owner, rr_type, rr_class, rr_data, expired)"
            " values(?, ?, ?, ?, ?)", tblname);

    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);

    now = time(NULL);
    //DBG("cache_rr now = %d\n", now);

    rcount = ldns_rr_list_rr_count(r);
    //DBG("begin to store rr...\n");

    /* cache CNAME */
    for (i = 0; i < rcount; i++) {

        int rtype = 0;
        r1 = ldns_rr_list_rr(r, i);
        t = ldns_rr_get_type(r1);

        /* onlye A, CNAME and AAAA */
        if (t != LDNS_RR_TYPE_CNAME) {
            //DBG("skip cache\n");
            continue;
        }

        if (cache_exists(r1, db, tblname) > 0) {
            DBG("cache CNAME exists, skip\n");
            continue;
        }

        rtype = LDNS_RR_TYPE_CNAME;

        //c = ldns_rr_get_class(r1);
        c = LDNS_RR_CLASS_IN;
        o = ldns_rr_owner(r1);
        d = ldns_rr_rdf(r1, 0);
        ttl = ldns_rr_ttl(r1);
        //DBG("cache_rr ttl = %d, now = %d\n", ttl, now);

        /* add 10min to ttl */
        ttl += (now + 600);

        //DBG("cache_rr ttl + now = %d\n", ttl);
        //DBG("store cache %d %d %d\n", c, rtype, ttl);
        /* owner */
        rc = sqlite3_bind_blob(stmt, 1, ldns_rdf_data(o), ldns_rdf_size(o),
                               SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            ERR("bind owner failed: %s\n", sqlite3_errmsg(db));
            goto err2;
        }

        /* type */
        rc = sqlite3_bind_int(stmt, 2, rtype);
        if (rc != SQLITE_OK) {
            ERR("bind type failed: %s\n", sqlite3_errmsg(db));
            goto err2;
        }

        /* class */
        rc = sqlite3_bind_int(stmt, 3, c);
        if (rc != SQLITE_OK) {
            ERR("bind class failed: %s\n", sqlite3_errmsg(db));
            goto err2;
        }

        /* expired */
        rc = sqlite3_bind_int(stmt, 5, ttl);
        if (rc != SQLITE_OK) {
            ERR("bind expired failed: %s\n", sqlite3_errmsg(db));
            goto err2;
        }


        char buf[128];

        buf[0] = 1;             /* count */
        buf[1] = ldns_rdf_size(d);  /* per_record_size */

        memcpy(&buf[2], ldns_rdf_data(d), ldns_rdf_size(d));

        /* rr_data */
        rc = sqlite3_bind_blob(stmt, 4, buf, ldns_rdf_size(d) + 2,
                               SQLITE_TRANSIENT);
        if (rc != SQLITE_OK) {
            ERR("bind rr_data failed: %s\n", sqlite3_errmsg(db));
            goto err2;
        }

        EXEC_SQL_NO_RESULT(stmt, ret, err2);
        //DBG("store CNAME success\n");
        /* reset */
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }
    
    ret = 0;
  err2:
    sqlite3_finalize(stmt);
  err1:
    return ret;
}

static int cache_rr_a_aaaa(const ldns_rr_list * r, sqlite3 * db,
                           const char *tblname)
{
    /* cache A or AAAA */
    int j = 0;
    char buf[256];
    int l = 0;
    int rtype = 0;
    ldns_rdf *rdata;
    ldns_rdf *owner = NULL;
    int ret = 0;
    uint32_t ttl = 0;
    ldns_rr *r1;
    int t;
    int i;
    int rcount;
    time_t now;
    sqlite3_stmt *stmt;
    char sql[512];

    sprintf(sql,
            "insert into %s (owner, rr_type, rr_class, rr_data, expired)"
            " values(?, ?, ?, ?, ?)", tblname);

    now = time(NULL);

    rcount = ldns_rr_list_rr_count(r);

    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);

    /* get owner, rtype, rlength */
    for (i = 0; i < rcount; i++) {
        r1 = ldns_rr_list_rr(r, i);
        t = ldns_rr_get_type(r1);
        if (t == LDNS_RR_TYPE_A || t == LDNS_RR_TYPE_AAAA) {
            rdata = ldns_rr_rdf(r1, 0);
            owner = ldns_rr_owner(r1);
            rtype =
                (t == LDNS_RR_TYPE_A ? LDNS_RR_TYPE_A : LDNS_RR_TYPE_AAAA);
            l = ldns_rdf_size(rdata);

            /* add 10min to ttl */
            ttl = ldns_rr_ttl(r1) + now + 600;
            buf[1] = l;
            break;
        }
    }

    /* copy data */
    for (i = 0; i < rcount; i++) {
        int pos;
        r1 = ldns_rr_list_rr(r, i);
        t = ldns_rr_get_type(r1);
        if (t == LDNS_RR_TYPE_A || t == LDNS_RR_TYPE_AAAA) {
            if (cache_exists(r1, db, tblname) > 0) {
                DBG("cache A or AAAA exists, skip\n");
                break;
            }
            rdata = ldns_rr_rdf(r1, 0);
            pos = 2 + j * l;
            memcpy(&buf[pos], ldns_rdf_data(rdata), l);
            j++;
        }
    }

    /* has A or AAAA */
    if (j) {

        buf[0] = j;

        /* owner */
        sqlite3_bind_blob(stmt, 1, ldns_rdf_data(owner),
                          ldns_rdf_size(owner), SQLITE_STATIC);
        /* type */
        sqlite3_bind_int(stmt, 2, rtype);
        /* class */
        sqlite3_bind_int(stmt, 3, LDNS_RR_CLASS_IN);
        /* rr_data */
        sqlite3_bind_blob(stmt, 4, buf, 2 + j * l, SQLITE_TRANSIENT);
        /* expired */
        sqlite3_bind_int(stmt, 5, ttl);
        EXEC_SQL_NO_RESULT(stmt, ret, err2);
    }

    ret = 0;

  err2:
    sqlite3_finalize(stmt);
  err1:
    return ret;
}

ldns_rr_list *lookup_cache(const ldns_rr * q, sqlite3 * db,
                           const char *tblname)
{
    int rtype;
    ldns_rdf *owner;
    ldns_rr_list *an = NULL;
    ldns_rr *r;
    int i;
    ldns_rdf *n_owner;

    owner = ldns_rr_owner(q);
    rtype = ldns_rr_get_type(q);

    /* the cache only support A or AAAA */
    if (rtype != LDNS_RR_TYPE_A && rtype != LDNS_RR_TYPE_AAAA) {
        return NULL;
    }

    an = ldns_rr_list_new();

    /* lookup CNAME first */
    lookup_cache_by_type(owner, LDNS_RR_TYPE_CNAME, an, db, tblname);

    /* if CNAME found, get the last CNAME rdata */
    n_owner = owner;
    for (i = 0; i < ldns_rr_list_rr_count(an); i++) {
        r = ldns_rr_list_rr(an, i);
        n_owner = ldns_rr_rdf(r, 0);
    }

    /* lookup the real query type */
    lookup_cache_by_type(n_owner, rtype, an, db, tblname);

    /* check if has the data with the query type */
    for (i = 0; i < ldns_rr_list_rr_count(an); i++) {
        r = ldns_rr_list_rr(an, i);
        if (ldns_rr_get_type(r) == rtype) {
            /* found */
            goto done;
        }
    }

    /* not found, free memory */
    goto err1;

  done:
    //ldns_rr_list_sort(an);
    return an;
  err1:
    /* free memory */
    ldns_rr_list_deep_free(an);
    an = NULL;
    goto done;
}

static int lookup_cache_by_type(ldns_rdf * owner, int type,
                                ldns_rr_list * ret, sqlite3 * db,
                                const char *tblname)
{
    if (type == LDNS_RR_TYPE_CNAME) {
        DBG("cache CNAME\n");
        lookup_cache_by_cname(owner, ret, db, tblname);
    } else if (type == LDNS_RR_TYPE_A) {
        DBG("cache A\n");
        lookup_cache_by_a_aaaa(owner, LDNS_RR_TYPE_A, ret, db, tblname);
    } else if (type == LDNS_RR_TYPE_AAAA) {
        DBG("cache AAAA\n");
        lookup_cache_by_a_aaaa(owner, LDNS_RR_TYPE_AAAA, ret, db, tblname);
    }
    return 0;
}

static int lookup_cache_by_cname(const ldns_rdf * owner,
                                 ldns_rr_list * retvalue, sqlite3 * db,
                                 const char *tblname)
{
    sqlite3_stmt *stmt;
    char sql[128];
    int ret = 0;
    char *q_name;
    size_t q_len;
    time_t now = time(NULL);

    sprintf(sql, "select owner, rr_type, rr_class, rr_data, expired from %s \
            where expired > %d and rr_type = ? and owner = ?",
            tblname, (int) now);

    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);

    //an = ldns_rr_list_new();
    q_name = (char *) ldns_rdf_data(owner);
    q_len = ldns_rdf_size(owner);
    while (1) {
        const char *n_owner = NULL;
        int rr_type = 0;
        int rr_class = 0;
        const char *rr_data = NULL;
        ldns_rr *new_rr = NULL;
        uint32_t ttl;

        if (sqlite3_bind_int(stmt, 1, LDNS_RR_TYPE_CNAME) != SQLITE_OK) {
            ERR("bind rr_type error: %s\n", sqlite3_errmsg(db));
            ret = -1;
            goto err2;
        }

        if (sqlite3_bind_blob(stmt, 2, q_name, q_len, SQLITE_STATIC) !=
            SQLITE_OK) {
            ERR("bind owner failed: %s\n", sqlite3_errmsg(db));
            ret = -1;
            goto err2;
        }
        //DBG("query CNAME in db...\n");
        EXEC_SQL_BEGIN(stmt, ret, err2);
        //DBG("found cname..\n");
        n_owner = sqlite3_column_blob(stmt, 0);
        rr_type = sqlite3_column_int(stmt, 1);
        rr_class = sqlite3_column_int(stmt, 2);
        rr_data = sqlite3_column_blob(stmt, 3);
        ttl = sqlite3_column_int(stmt, 4);
        //DBG("get_rr get ttl = %d, now = %d\n", ttl, now);
        ttl -= now;
        //DBG(" ttl - now = %d\n", ttl);
        new_rr = ldns_rr_new();
        ldns_rdf *new_owner_rdf =
            ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME,
                                  sqlite3_column_bytes(stmt, 0), n_owner);
        ldns_rr_set_owner(new_rr, new_owner_rdf);
        ldns_rr_set_type(new_rr, rr_type);
        ldns_rr_set_class(new_rr, rr_class);
        ldns_rr_set_ttl(new_rr, ttl);
        ldns_rdf *new_rdf_cname;
        new_rdf_cname =
            ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME,
                                  sqlite3_column_bytes(stmt, 3) - 2,
                                  rr_data + 2);
        ldns_rr_push_rdf(new_rr, new_rdf_cname);
        ldns_rr_list_push_rr(retvalue, new_rr);

        /* change query name to CNAME destination */
        q_name = (char *) ldns_rdf_data(new_rdf_cname);
        q_len = ldns_rdf_size(new_rdf_cname);

        EXEC_SQL_END;

        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        if (new_rr == NULL) {
            //DBG("query CNAME end\n");
            break;
        }
    }
  err2:
    sqlite3_finalize(stmt);
  err1:
    return ret;
}

static int lookup_cache_by_a_aaaa(ldns_rdf * owner, int type,
                                  ldns_rr_list * retvalue, sqlite3 * db,
                                  const char *tblname)
{
    sqlite3_stmt *stmt;
    char sql[128];
    int ret = 0;
    const char *dname = NULL;
    int rr_type;
    int rr_class;
    const char *rr_data;
    uint32_t ttl = 0;
    int count, length;
    int i;
    size_t dname_len;

    time_t now = time(NULL);

    sprintf(sql, "select owner, rr_type, rr_class, rr_data, expired from %s \
            where expired > %d and rr_type = ? and owner = ?",
            tblname, (int) now);

    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);

    if (sqlite3_bind_int(stmt, 1, type) != SQLITE_OK) {
        ERR("bind type failed: %s\n", sqlite3_errmsg(db));
        ret = -1;
        goto err2;
    }

    if (sqlite3_bind_blob
        (stmt, 2, ldns_rdf_data(owner), ldns_rdf_size(owner),
         SQLITE_STATIC) != SQLITE_OK) {
        ERR("bind owner failed: %s\n", sqlite3_errmsg(db));
        ret = -1;
        goto err2;
    }
    //DBG("query type %d\n", t);
    EXEC_SQL_BEGIN(stmt, ret, err2);
    //DBG("fond ....\n");
    dname = sqlite3_column_blob(stmt, 0);
    rr_type = sqlite3_column_int(stmt, 1);
    rr_class = sqlite3_column_int(stmt, 2);
    rr_data = sqlite3_column_blob(stmt, 3);
    ttl = sqlite3_column_int(stmt, 4);
    //DBG("get rr get ttl %d, now %d\n", ttl, now);
    ttl -= now;
    //DBG("ttl - now = %d\n", ttl);
    dname_len = sqlite3_column_bytes(stmt, 0);

    /* count */
    count = rr_data[0];

    /* length */
    length = rr_data[1];
    for (i = 0; i < count; i++) {
        ldns_rr *new_rr = ldns_rr_new();
        ldns_rdf *new_rdf;
        new_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME,
                                        dname_len, dname);

        /* domain name */
        ldns_rr_set_owner(new_rr, new_rdf);

        ldns_rr_set_type(new_rr, rr_type);
        ldns_rr_set_class(new_rr, rr_class);
        ldns_rr_set_ttl(new_rr, ttl);

        /* A or AAAA */
        new_rdf =
            ldns_rdf_new_frm_data(
                    type == LDNS_RR_TYPE_A ? LDNS_RDF_TYPE_A : LDNS_RDF_TYPE_AAAA,
                    length, rr_data + 2 + i * length);
        ldns_rr_push_rdf(new_rr, new_rdf);

        /* add to list */
        ldns_rr_list_push_rr(retvalue, new_rr);

    }
    EXEC_SQL_END;
  err2:
    sqlite3_finalize(stmt);
  err1:
    return ret;
}

int delete_expired_rr(sqlite3 * db, const char *tblname)
{
    sqlite3_stmt *stmt;
    char sql[100];
    time_t now;
    int ret = 0;
    now = time(NULL);
    sprintf(sql, "delete from %s where expired <= %d", tblname, (int) now);

    PREPARE_SQL(db, sql, strlen(sql), stmt, ret, err1);
    EXEC_SQL_NO_RESULT(stmt, ret, err2);
  err2:
    sqlite3_finalize(stmt);
  err1:
    return ret;
}
