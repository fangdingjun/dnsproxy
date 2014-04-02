#include <glib.h>
#include <string.h>
#include <gio/gio.h>
#ifdef G_OS_WIN32
#include <gio/gnetworking.h>
#endif

#include "dns.h"

static gchar *local_ip="0.0.0.0";
static gchar *server_ip="8.8.8.8";
gchar *blacklist = "1.1.1.1|255.255.255.255|74.125.127.102|74.125.155.102|74.125.39.102|74.125.39.113|209.85.229.138|4.36.66.178|8.7.198.45|37.61.54.158|46.82.174.68|59.24.3.173|64.33.88.161|64.33.99.47|64.66.163.251|65.104.202.252|65.160.219.113|66.45.252.237|72.14.205.104|72.14.205.99|78.16.49.15|93.46.8.89|128.121.126.139|159.106.121.75|169.132.13.103|192.67.198.6|202.106.1.2|202.181.7.85|203.161.230.171|203.98.7.65|207.12.88.98|208.56.31.43|209.145.54.50|209.220.30.174|209.36.73.33|209.85.229.138|211.94.66.147|213.169.251.35|216.221.188.182|216.234.179.13|243.185.187.3|243.185.187.39";

struct dnsmsginfo{
    GSocket *sock; /* listen socket */
    GSocketAddress *caddr; /* client address */
    GString *cmsg; /* dns msg from client */
};

// function define
gboolean read_from_server(GSocket *sock, GIOCondition cond, gpointer data);
gboolean read_from_client(GSocket *sock, GIOCondition cond, gpointer user_data);
gboolean process_client_msg(struct dnsmsginfo *msg);

/* the callback function for client data in
 * */
gboolean read_from_client(GSocket *sock, GIOCondition cond, gpointer user_data){
    struct dnsmsginfo *msg;
    GSocketAddress *caddr=NULL;
    GError *error=NULL;
    gssize nbytes;
    gchar buf[512];
    while(1){
        caddr=NULL;
        error=NULL;

        /* receive data */
        if((nbytes=g_socket_receive_from(
                        sock,&caddr,buf,512,NULL,&error)) == -1){ // receive error
            if(error->code == G_IO_ERROR_WOULD_BLOCK){
                break;
            }
            g_warning(error->message);
            g_error_free(error);
            error=NULL;
            break;
        }
        g_debug("receive %d bytes from client %s:%d",
                nbytes,
                g_inet_address_to_string(
                    g_inet_socket_address_get_address(
                        (GInetSocketAddress*)caddr)),
                g_inet_socket_address_get_port(
                    (GInetSocketAddress*)caddr)
                );

        /* allocate memory */
        msg=g_new0(struct dnsmsginfo,1);
        msg->sock=sock;
        msg->caddr=caddr;
        msg->cmsg=g_string_new_len(buf,nbytes);

        /* process msg */
        process_client_msg(msg);
    }
    return TRUE;
}

/* send the msg to server and create the event source and watch it */
gboolean process_client_msg(struct dnsmsginfo *msg){
    GSocket *sock; /* server socket */
    GError *error=NULL;
    GSource *esrc;
    GSocketAddress *saddr; /* server address */

    g_debug("process client msg");
    g_debug("create socket to server");
    sock=g_socket_new(G_SOCKET_FAMILY_IPV4,
            G_SOCKET_TYPE_DATAGRAM,
            G_SOCKET_PROTOCOL_UDP,&error);
    if(sock == NULL){// create socket error
        g_warning(error->message);
        g_error_free(error);
        error=NULL;
        goto err1;
    }

    g_debug("set server socket nonblock");
    g_socket_set_blocking(sock,FALSE);

    g_debug("create event source for server socket");
    esrc=g_socket_create_source(sock,G_IO_IN,NULL);

    g_debug("set callback function");
    g_source_set_callback(esrc,read_from_server,msg,NULL);

    g_debug("attach event to default context");
    g_source_attach(esrc,g_main_context_default());

    /* create server socket address */
    saddr=g_inet_socket_address_new(
            g_inet_address_new_from_string(server_ip),
            53);

    g_debug("send msg to server");
    if((g_socket_send_to(sock,saddr,msg->cmsg->str,msg->cmsg->len,NULL,&error) == -1)){
        // on error
        g_warning(error->message);
        g_error_free(error);
        error=NULL;
        goto err2;
    }
    g_debug("send msg to server success");
err2:
    g_object_unref(sock);
err1:
    return FALSE;
}

/* the callback function for server data in */
gboolean read_from_server(GSocket *sock, GIOCondition cond, gpointer data){
    struct dnsmsginfo *msg;
    GSocketAddress *saddr=NULL; /* server address */
    gchar buf[512];
    GError *error=NULL;
    gssize nbytes;
    GSource *csrc; // source
    gint black_ip_found=0;

    msg=(struct dnsmsginfo *)data; /* passed from callback */

    g_debug("receive from server");
    while(1){
        saddr = NULL;
        error=NULL;
        if((nbytes=g_socket_receive_from(
                        sock,&saddr,buf,512,NULL,&error)) == -1){
            /* error */
            if(error->code == G_IO_ERROR_WOULD_BLOCK){
                g_error_free(error);
                error=NULL;

                if(black_ip_found){
                    return TRUE;
                }
                
                break;
            }
            g_warning(error->message);
            g_error_free(error);
            error=NULL;
            break;
        }
        g_debug("receive %d bytes from server %s:%d",
                nbytes,
                g_inet_address_to_string(g_inet_socket_address_get_address(
                        (GInetSocketAddress*)saddr)),
                    g_inet_socket_address_get_port(
                        (GInetSocketAddress*)saddr));
        
        struct dns_msg *m;
        m=g_new0(struct dns_msg,1);
        m->msg_len=nbytes;
        m->buf=g_malloc(nbytes);
        memcpy(m->buf,buf,nbytes);
        struct dns_rr *r;
        gchar *p1;
        parse_msg(m);
        for(r=m->an;r!=NULL;r=r->next){
            if(r->type ==  RR_A){
                p1=g_strstr_len(blacklist,-1,(gchar*)r->rdata);
                if(p1){
                    g_debug("found blacklist ip %s",(gchar *)r->rdata);
                    black_ip_found = 1;
                    break;
                }
            }
        }
        free_dns_msg(m);
        //free(m);
        if(black_ip_found){
            g_warning("badip found, continue");
            continue;
        }

        g_debug("send to client");
        if((g_socket_send_to(
                        msg->sock,msg->caddr,buf,nbytes,NULL,&error)) == -1){
            /* error */
            g_warning(error->message);
            g_error_free(error);
            error=NULL;
            break;
        }
    }

    g_debug("get current source");
    csrc=g_main_current_source();
    if(csrc){
        g_debug("destroy source");
        g_source_destroy(csrc);
        g_debug("unref source");
        g_source_unref(csrc);
    }

    g_debug("free cmsg");
    g_string_free(msg->cmsg,TRUE);

    g_debug("free msg");
    g_free(msg);

    g_debug("close server socket");
    //g_object_unref(sock);
    g_socket_close(sock,NULL);

    /* return FALSE will remove the source from main loop */
    return FALSE;
}

static GOptionEntry entries[]={
    {"local_ip",'l',0,G_OPTION_ARG_STRING,&local_ip,"local ip address to listen on","IP"},
    {"server",'s',0,G_OPTION_ARG_STRING,&server_ip,"the upstream dns server to forward to","SERVER"},
    {NULL}
};
int main(int argc, char *argv[]){
    GSocket *sock; /* listen socket */
    GSocketAddress *laddr; /* local address */
    GSource *esrc;
    GMainLoop *mloop;
    GError *error=NULL;
    GOptionContext *context;

    //gint i;

    context = g_option_context_new("- dns proxy server");
    g_option_context_add_main_entries(context, entries, NULL);
    //g_option_context_add_group(context, );
    if(!g_option_context_parse(context, &argc, &argv, &error)){
        g_print("option parsing failed: %s\n", error->message);
        g_error_free(error);
        error=NULL;
        goto err1;
    }

    g_message("beginning...");

    /* initial */
    g_type_init();
#ifdef G_OS_WIN32
    g_networking_init();
#endif

    g_debug("create listen socket");
    sock=g_socket_new(G_SOCKET_FAMILY_IPV4,
            G_SOCKET_TYPE_DATAGRAM,
            G_SOCKET_PROTOCOL_UDP,&error);
    if(sock == NULL){
        /* error */
        g_warning(error->message);
        g_error_free(error);
        error=NULL;
        goto err1;
    }

    g_debug("set listen socket nonblock");
    g_socket_set_blocking(sock,FALSE);

    /* create local address */
    laddr=g_inet_socket_address_new(
            g_inet_address_new_from_string(local_ip),
            53);

    g_debug("bind to local");
    if(!g_socket_bind(sock,laddr,TRUE,&error)){
        /* bind error */
        g_warning(error->message);
        g_error_free(error);
        error=NULL;
        goto err2;
    }
    g_message("listen to %s:%d", local_ip,53); 
    g_message("forward to server %s:%d", server_ip, 53);

    g_debug("create event source from listen socket");
    esrc=g_socket_create_source(sock,G_IO_IN,NULL);

    g_source_set_callback(esrc,read_from_client,NULL,NULL);
    g_source_attach(esrc,g_main_context_default());

    g_debug("creat main loop");
    mloop=g_main_loop_new(NULL,FALSE);
    
    /* this will run forever */
    g_debug("running...");
    g_main_loop_run(mloop);

    /* clean */
    g_main_loop_unref(mloop);
    g_source_unref(esrc);
    g_object_unref(sock);

    g_warning("end");
    return 0;
err2:
    g_object_unref(sock);
err1:
    return -1;
}
