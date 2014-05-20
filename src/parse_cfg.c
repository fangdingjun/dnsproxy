#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dnsproxy.h"

char *skip_space_at_begin(char *p){
    char *p1;
    p1=p;
    if(!p) return NULL;
    while(isspace(*p1)) p1++;
    return p1;
}

char *skip_space_at_end(char *p){
    char *p1;
    if(!p) return NULL;
    p1=p;
    //p1=strchr(p,'\0');
    while(isspace(*p1)) p1--;
    p1++;
    return p1;
}

int parse_cfg(char *filename, struct arg_map *args){
    char *fn;
    FILE *fp;
    int i;
    char buf[1024];
    fn=filename;
    if(filename == NULL) return 0;
    fp=fopen(fn,"r");
    if(fp == NULL){
        //perror(fn);
        fprintf(stderr, "open %s failed\n", fn);
        return -1;
    }
    while(fgets(buf,1024,fp) != NULL){
        char *p1;
        char *p2;
        char *p3;
        char *k;
        char *v;
        int l;
        p1=buf;
        while(isspace(*p1)) p1++;
        if(*p1 == '#') continue;
        if(*p1 == '\0') continue;
        //printf("%s",buf);
        p2=strchr(p1,'=');
        if(!p2) continue;
        p3=p2;
        p2--;

        p2=skip_space_at_end(p2);

        l=p2-p1;
        k=(char *)malloc(l+1);
        strncpy(k,p1,l);
        k[l]='\0';

        //printf("get key: '%s'", k);

        p3++;
        p1=p3;;
        p1=skip_space_at_begin(p1);

        p2=strchr(p1,'\r');
        if(!p2) p2=strchr(p1,'\n');
        if(!p2) p2=strchr(p1,'\0');
        p2=skip_space_at_end(p2);
        l=p2-p1;
        v=(char *)malloc(l+1);
        strncpy(v,p1,l);
        v[l]='\0';
        //printf(" = '%s'\n", v);
        int found = 0;
        for(i=0;args[i].name!=NULL;i++){
            if(strcmp(args[i].name, k) == 0){
                found = 1;
                //printf("aaa: %s %d %p\n", args[i].name, args[i].type,args[i].addr);
                if(args[i].type == ARG_STRING){
                    *((char **)(args[i].addr)) = v;
                }else if (args[i].type == ARG_INT){
                    *((int *)(args[i].addr)) = atoi(v);
                    free(v);
                    v=NULL;
                }else if(args[i].type == ARG_STR_ARRARY){
                    char **ap;
                    char *ap1[10];
                    //char *k1;
                    char *pp1;
                    char *pp2;
                    char *pp3;
                    int pos=0;
                    ap=(char **)malloc(sizeof(ap1));
                    pp1=v;
                    while(1){
                        pp1=skip_space_at_begin(pp1);
                        pp2=strchr(pp1,',');
                        if(!pp2) pp2 = strchr(pp1,'\0');
                        pp3=pp2;
                        pp2--;
                        pp2=skip_space_at_end(pp2);
                        l=pp2-pp1;
                        ap[pos]=(char *)malloc(l+1);
                        strncpy(ap[pos],pp1,l);
                        ap[pos][l]='\0';
                        if(*pp3 == '\0') break;
                        pp3++;
                        pp1=pp3;
                        pos++;
                        if(pos > 9) break;
                    }
                    ap[pos]=NULL;
                    *((char ***)(args[i].addr)) = ap;
                    free(v);
                }else{
                    printf("unknown type\n");
                    free(v);
                }
                break;
            }
        }
        if(!found){
            printf("unkown key: %s\n", k);
            free(k);
            k=NULL;
            free(v);
            v=NULL;
        }else{
            free(k);
            k=NULL;
        }
    }
    fclose(fp);
    return 0;
}


int get_blackip(char *filename, char **ips){
    char *buf1;
    char buf2[1024];
    FILE *fp;
    if(filename == NULL){
        *ips=NULL;
        return -1;
    }
    buf1=(char *)malloc(65536);
    fp=fopen(filename,"r");
    if(fp == NULL){
        //perror(filename);
        fprintf(stderr, "open %s failed\n", filename);
        *ips=NULL;
        free(buf1);
        return -1;
    }
    char *p1,*p2;
    int l;
    buf2[0]='\0';
    buf1[0]='\0';
    while(fgets(buf2,1024,fp) != NULL){
        p1=buf2;
        p1=skip_space_at_begin(p1);
        if(*p1 == '#' || *p1 == '\0') continue;
        p2=strchr(p1,'\0');
        p2--;
        p2=skip_space_at_end(p2);
        l=p2-p1;
        if(buf1[0] != '\0'){
            strcat(buf1,"|");
        }
        strncat(buf1,p1,l);
    }
    fclose(fp);
    l=strlen(buf1);
    buf1=realloc(buf1,l+1);
    *ips=buf1;

    return 0;
}
