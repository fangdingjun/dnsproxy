#============================================
# Filename:
#    parse_cfg.c
# Author:
#    fangdingjun@gmail.com
# License:
#   GPLv3 (http://www.gnu.org/licenses/gpl-3.0.html)
# Description:
#   this file contain the functions to parse config file
#   and  assign the result to variable by a structure
#============================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dnsproxy.h"

char *skip_space_at_begin(char *p)
{
    char *p1;
    p1 = p;
    if (!p)
        return NULL;
    while (isspace(*p1))
        p1++;
    return p1;
}

char *skip_space_at_end(char *p)
{
    char *p1;
    if (!p)
        return NULL;
    p1 = p;
    //p1=strchr(p,'\0');
    while (isspace(*p1))
        p1--;
    p1++;
    return p1;
}

int split_two_parts(char *str, int comma, char **part1, char **part2)
{
    char *p1;
    char *p2;
    char *p3;
    int l;

    /* eat space at beginning */
    p1 = str;
    p1 = skip_space_at_begin(p1);

    p2 = strchr(p1, comma);

    /* no comma found */
    if (!p2) {
        p2 = strchr(p1, '\0');
    }

    p3 = p2;

    p2--;
    p2 = skip_space_at_end(p2);

    l = p2 - p1;
    if (l) {
        *part1 = malloc(l + 1);
        if (*part1) {
            strncpy(*part1, p1, l);
            (*part1)[l] = '\0';
        }
    } else {
        *part1 = NULL;
    }

    if (*p3 == '\0') {
        *part2 = NULL;
        return 0;
    }
    p3++;
    p1 = p3;
    p1 = skip_space_at_begin(p1);
    p2 = strchr(p1, '\0');
    p2--;
    p2 = skip_space_at_end(p2);

    l = p2 - p1;
    if (l) {
        *part2 = malloc(l + 1);
        if (*part2) {
            strncpy(*part2, p1, l);
            (*part2)[l] = '\0';
        }
    } else {
        *part2 = NULL;
    }

    return 0;
}

char **split(char *str, int comma)
{
    char **arr;
    char *p;
    int pos = 0;
    int maxsize;

    maxsize = 100;

    arr = malloc(maxsize * sizeof(char *));
    if (!arr) {
        fprintf(stderr, "out of memory\n");
        return NULL;
    }
    memset(arr, 0, maxsize * sizeof(char *));
    p = malloc(strlen(str) + 1);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        free(arr);
        return NULL;
    }
    strcpy(p, str);
    while (1) {
        char *p1 = NULL;
        char *p2 = NULL;
        split_two_parts(p, comma, &p1, &p2);
        free(p);
        if (p1) {
            arr[pos] = p1;
            pos++;
            if (pos == (maxsize - 1)) {
                maxsize = maxsize << 1;
                arr = realloc(arr, maxsize);
            }
        }
        if (!p2)
            break;
        p = p2;
    }
    arr[pos] = NULL;
    arr = realloc(arr, (pos + 1) * sizeof(char *));
    return arr;
}

/* parse key-value configfile, use struct arg_map */
int parse_cfg(char *filename, struct arg_map *args)
{
    char *fn;
    FILE *fp;
    int i;
    char buf[1024];
    fn = filename;
    if (filename == NULL)
        return 0;
    fp = fopen(fn, "r");
    if (fp == NULL) {
        //perror(fn);
        fprintf(stderr, "open %s failed\n", fn);
        return -1;
    }
    while (fgets(buf, 1024, fp) != NULL) {
        char *p1;
        char *p2;
        //char *p3;
        char *k;
        char *v;
        //int l;
        p1 = buf;

        /* eat space */
        p1 = skip_space_at_begin(p1);

        /* ignore comments */
        if (*p1 == '#')
            continue;

        /* empty line, ignore */
        if (*p1 == '\0')
            continue;

        p2 = strchr(p1, '=');

        /* no '=' found, ignore */
        if (!p2)
            continue;

        split_two_parts(p1, '=', &k, &v);

        if (k == NULL || v == NULL) {
            if (k)
                free(k);
            if (v)
                free(v);
            continue;
        }
        /* process argument map */
        int found = 0;
        for (i = 0; args[i].name != NULL; i++) {
            if (strcmp(args[i].name, k) == 0) {
                found = 1;
                //printf("aaa: %s %d %p\n", args[i].name, args[i].type,args[i].addr);
                if (args[i].type == ARG_STRING) {
                    *((char **) (args[i].addr)) = v;
                } else if (args[i].type == ARG_INT) {
                    *((int *) (args[i].addr)) = atoi(v);
                    free(v);
                    v = NULL;
                } else if (args[i].type == ARG_STR_ARRARY) {
                    char **ap;
                    ap = split(v, ',');
                    *((char ***) (args[i].addr)) = ap;
                    free(v);
                    v = NULL;
                } else {
                    printf("unknown type\n");
                    free(v);
                    v = NULL;
                }

                /* found one, goto out */
                break;
            }                   /* if strcmp */
        }                       /* for */
        if (!found) {
            printf("unkown key: %s\n", k);
            free(k);
            k = NULL;
            free(v);
            v = NULL;
        } else {
            free(k);
            k = NULL;
        }
    }                           /* while(fgets) */
    fclose(fp);
    return 0;
}


int get_blackip(char *filename, char **ips)
{
    char *buf1;
    char buf2[1024];
    FILE *fp;
    if (filename == NULL) {
        *ips = NULL;
        return -1;
    }
    buf1 = (char *) malloc(65536);
    if(!buf1){
        fprintf(stderr, "out of memory\n");
        *ips = NULL;
        return -1;
    }
    fp = fopen(filename, "r");
    if (fp == NULL) {
        //perror(filename);
        fprintf(stderr, "open %s failed\n", filename);
        *ips = NULL;
        free(buf1);
        return -1;
    }
    char *p1, *p2;
    int l;
    buf2[0] = '\0';
    buf1[0] = '\0';
    while (fgets(buf2, 1024, fp) != NULL) {
        p1 = buf2;
        p1 = skip_space_at_begin(p1);
        if (*p1 == '#' || *p1 == '\0')
            continue;
        p2 = strchr(p1, '\0');
        p2--;
        p2 = skip_space_at_end(p2);
        l = p2 - p1;
        if (buf1[0] != '\0') {
            strcat(buf1, "|");
        }
        strncat(buf1, p1, l);
    }
    fclose(fp);
    l = strlen(buf1);
    buf1 = realloc(buf1, l + 1);
    *ips = buf1;

    return 0;
}
