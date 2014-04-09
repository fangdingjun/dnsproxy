#include <glib.h>
#include <string.h>
#include <gio/gio.h>
#ifdef G_OS_WIN32
#include <gio/gnetworking.h>
#endif                          /*  win32 */

#include "dns.h"

static gchar *local_ip = "0.0.0.0";

//static gchar *server_ip = "8.8.8.8";

/* the remote dns server to forward to */
static gchar *servers[] = {
    "8.8.8.8",
    "223.6.6.6",
    "114.114.114.114",
    "4.2.2.2",
    NULL
};

/* server GSocketAddress list */
GList *srvlist = NULL;

/*
 * gfw bad ip list from https://github.com/goagent/goagent/blob/3.0/local/proxy.ini
 *
 */
gchar *blacklist =
    "1.1.1.1|255.255.255.255|74.125.127.102|74.125.155.102|74.125.39.102|74.125.39.113|209.85.229.138|4.36.66.178|8.7.198.45|37.61.54.158|46.82.174.68|59.24.3.173|64.33.88.161|64.33.99.47|64.66.163.251|65.104.202.252|65.160.219.113|66.45.252.237|72.14.205.104|72.14.205.99|78.16.49.15|93.46.8.89|128.121.126.139|159.106.121.75|169.132.13.103|192.67.198.6|202.106.1.2|202.181.7.85|203.161.230.171|203.98.7.65|207.12.88.98|208.56.31.43|209.145.54.50|209.220.30.174|209.36.73.33|209.85.229.138|211.94.66.147|213.169.251.35|216.221.188.182|216.234.179.13|243.185.187.3|243.185.187.39";

/* this struct will pass to event callback */
struct dnsmsginfo {
    GSocket *sock_listen;              /* listen socket */
    GSocketAddress *client_addr;      /* client address */
    GString *client_msg;              /* dns msg from client */
    GSource *timeout_source;           /* timeout source */
    GSource *srv_source;               /* server source */
    GSocket *sock_srv;          /* server socket */
};

// function define
/* server response callback */
gboolean read_from_server(GSocket * sock, GIOCondition cond,
                          gpointer data);

/* client request callback */
gboolean read_from_client(GSocket * sock, GIOCondition cond,
                          gpointer user_data);

/* send data to server */
gboolean process_client_msg(struct dnsmsginfo *msg);

/* server response timeout callback */
gboolean timeout_server(gpointer data);

/*
 * the callback function for client request
 *
 */
gboolean read_from_client(GSocket * sock, GIOCondition cond,
                          gpointer user_data)
{
    struct dnsmsginfo *msg;
    GSocketAddress *caddr = NULL;
    GError *error = NULL;
    GSource *timeout;
    gssize nbytes;
    gchar buf[512];
    gchar *addr;

    while (1) {
        caddr = NULL;
        error = NULL;

        /* receive data */
        if ((nbytes = g_socket_receive_from(sock, &caddr, buf, 512, NULL, &error)) == -1) { // receive error

            if (caddr) {
                g_object_unref(caddr);
            }

            if (error->code == G_IO_ERROR_WOULD_BLOCK) {    // no data
                g_error_free(error);
                error = NULL;
                break;
            }
            g_warning("%s", error->message);
            g_error_free(error);
            error = NULL;
            break;
        }
        GInetAddress *cinet;
        cinet = g_inet_socket_address_get_address((GInetSocketAddress *)
                                                  caddr);
        addr = g_inet_address_to_string(cinet);

        g_debug("receive %d bytes from client %s:%d", nbytes,
                addr, g_inet_socket_address_get_port((GInetSocketAddress *)
                                                     caddr)
            );
        //g_object_unref(cinet);
        g_free(addr);

        /* allocate memory */
        msg = g_new0(struct dnsmsginfo, 1);

        msg->sock_listen = sock;
        msg->client_addr = caddr;
        msg->client_msg = g_string_new_len(buf, nbytes);

        /* create server response timeout event source */
        timeout = g_timeout_source_new_seconds(5);
        g_source_set_callback(timeout, timeout_server, msg, NULL);
        g_source_attach(timeout, NULL);

        /* save */
        msg->timeout_source = timeout;

        g_source_unref(timeout);

        /* process msg */
        process_client_msg(msg);
    }

    /* must return TRUE to keep event source */
    return TRUE;
}


/* callback from timeout for server response timeout */
gboolean timeout_server(gpointer data)
{
    struct dnsmsginfo *msg;

    msg = (struct dnsmsginfo *) data;

    g_debug("timeout callback, free memory");

    /* destroy server response event source */
    g_debug("destroy srv source");
    g_source_destroy(msg->srv_source);
    //g_debug("unref msg->srv");
    //g_source_unref(msg->srv);

    /* free client request message */
    g_debug("free client message");
    g_string_free(msg->client_msg, TRUE);

    //g_debug("close server socket");
    //g_object_unref(msg->sock_srv);
    //g_socket_close(msg->sock_srv, NULL);

    //g_debug("destroy timeout source");
    //g_source_destroy(msg->timeout);
    //g_debug("unref timeout source");
    //g_source_unref(msg->timeout);

    g_debug("unref client address");
    g_object_unref(msg->client_addr);

    /* free itself */
    g_debug("free dnsmsginfo struct");
    g_free(msg);

    /* return FALSE will remove this source */
    return FALSE;
}


/* send the msg to server and create the event source and watch it */
gboolean process_client_msg(struct dnsmsginfo * msg)
{
    GSocket *sock;              /* server socket */
    GError *error = NULL;
    GSource *esrc;              /* server response event source */
    GSocketAddress *saddr;      /* server address */

    GList *s;

    g_debug("process client msg");

    g_debug("create socket to server");
    sock =
        g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
                     G_SOCKET_PROTOCOL_UDP, &error);
    if (sock == NULL) {         // create socket error
        g_warning("%s", error->message);
        g_error_free(error);
        error = NULL;
        goto err1;
    }

    msg->sock_srv = sock;

    g_debug("set server socket nonblock");
    g_socket_set_blocking(sock, FALSE);

    g_debug("create event source for server socket");
    esrc = g_socket_create_source(sock, G_IO_IN, NULL);

    g_debug("set callback function");
    g_source_set_callback(esrc, read_from_server, msg, NULL);

    msg->srv_source = esrc;

    g_debug("attach event to default context");
    g_source_attach(esrc, NULL);

    g_source_unref(esrc);
    g_object_unref(sock);

    /* create server socket address */
    /*
       saddr =
       g_inet_socket_address_new(g_inet_address_new_from_string
       (server_ip), 53);
     */

    g_debug("send msg to server");
    GInetAddress *sinet;

    /* send the data to all servers */
    for (s = srvlist; s && s->next != srvlist; s = s->next) {
        gchar *ip;
        saddr = (GSocketAddress *) s->data;
        sinet = g_inet_socket_address_get_address((GInetSocketAddress *)
                                                  saddr);
        ip = g_inet_address_to_string(sinet);

        g_debug("send to %s:%d", ip, 53);

        if ((g_socket_send_to
             (sock, saddr, msg->client_msg->str, msg->client_msg->len, NULL,
              &error) == -1)) {
            // on error
            g_warning("%s", error->message);
            g_error_free(error);
            error = NULL;
            goto err2;
        }

        g_debug("send msg to server %s:%d success", ip, 53);
        //g_object_unref(sinet);
        g_free(ip);
    }

    return TRUE;

  err2:
    /* destroy the socket */
    g_object_unref(sock);
  err1:
    return FALSE;
}


/* the callback function for server response */
gboolean read_from_server(GSocket * sock, GIOCondition cond, gpointer data)
{
    struct dnsmsginfo *msg;
    GSocketAddress *saddr = NULL;   /* server address */
    gchar buf[512];
    GError *error = NULL;
    gssize nbytes;
    //GSource *csrc;              // event source for server
    gint black_ip_found = 0;
    gchar *addr;

    msg = (struct dnsmsginfo *) data;   /* passed from callback */

    g_debug("receive from server");
    while (1) {
        saddr = NULL;
        error = NULL;

        if ((nbytes =
             g_socket_receive_from(sock, &saddr, buf, 512, NULL,
                                   &error)) == -1) {

            if (saddr) {
                g_object_unref(saddr);
            }

            /* no data */
            if (error->code == G_IO_ERROR_WOULD_BLOCK) {
                g_error_free(error);
                error = NULL;

                /* black list ip found, to wait next data */
                if (black_ip_found) {
                    return TRUE;
                }

                break;
            }

            /* error */
            g_warning("%s", error->message);
            g_error_free(error);
            error = NULL;
            break;
        }
        GInetAddress *sinet;
        sinet = g_inet_socket_address_get_address((GInetSocketAddress *)
                                                  saddr);
        addr = g_inet_address_to_string(sinet);

        g_debug("receive %d bytes from server %s:%d", nbytes,
                addr, g_inet_socket_address_get_port((GInetSocketAddress *)
                                                     saddr)
            );
        //g_object_unref(sinet);
        g_free(addr);

        g_object_unref(saddr);

        /* prepare for parsing dns message */
        struct dns_msg *m;
        m = g_new0(struct dns_msg, 1);
        m->msg_len = nbytes;
        m->buf = g_malloc0(nbytes);
        memcpy(m->buf, buf, nbytes);
        struct dns_rr *r;
        gchar *p1;

        /* parse */
        parse_msg(m);

        /* check blacklist ip */
        for (r = m->an; r != NULL; r = r->next) {
            if (r->type == RR_A) {
                p1 = g_strstr_len(blacklist, -1, (gchar *) r->rdata);
                if (p1) {
                    g_debug("found blacklist ip %s", (gchar *) r->rdata);
                    black_ip_found = 1;
                    break;
                }
            }
        }

        /* free */
        free_dns_msg(m);

        /* found */
        if (black_ip_found) {
            g_warning("badip found, continue");
            continue;
        }

        g_debug("send to client");
        if ((g_socket_send_to
             (msg->sock_listen, msg->client_addr, buf, nbytes, NULL, &error)) == -1) {

            /* error */
            g_warning("%s", error->message);
            g_error_free(error);
            error = NULL;
            break;
        }
    }

    /*
       g_debug("destroy srv evt source");
       g_source_destroy(msg->srv);
       g_source_unref(msg->srv);

       g_debug("free client request message");
       g_string_free(msg->cmsg, TRUE);

       g_debug("remove timeout event");
       g_source_destroy(msg->timeout);
       g_source_unref(msg->timeout);

       g_debug("free client address");
       g_object_unref(msg->caddr);

       g_debug("close server socket");
       g_object_unref(msg->sock_srv);
       //g_socket_close(msg->sock_srv, NULL);

       g_debug("free struct dnsmsginfo");
       g_free(msg);
     */

    /* return FALSE will remove the source from main loop */
    return TRUE;
}

/* command line options */
static GOptionEntry entries[] = {
    {"local_ip", 'l', 0, G_OPTION_ARG_STRING, &local_ip,
     "local ip address to listen on", "IP"},
    /*{"server", 's', 0, G_OPTION_ARG_STRING, &server_ip,
       "the upstream dns server to forward to",
       "SERVER"},
     */
    {NULL}
};

int main(int argc, char *argv[])
{
    GSocket *sock;              /* listen socket */
    GSocketAddress *laddr;      /* local address */
    GSource *esrc;
    GMainLoop *mloop;
    GError *error = NULL;
    GOptionContext *context;

    gint i;

    context = g_option_context_new("- dns proxy server");
    g_option_context_add_main_entries(context, entries, NULL);

    //g_option_context_add_group(context, );
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_print("option parsing failed: %s\n", error->message);
        g_error_free(error);
        error = NULL;
        goto err1;
    }

    g_message("beginning...");

    /* initial */
    g_type_init();

#ifdef G_OS_WIN32
    g_networking_init();
#endif                          /*  */

    g_debug("create listen socket");
    sock =
        g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
                     G_SOCKET_PROTOCOL_UDP, &error);
    if (sock == NULL) {

        /* error */
        g_warning("%s", error->message);
        g_error_free(error);
        error = NULL;
        goto err1;
    }

    g_debug("set listen socket nonblock");
    g_socket_set_blocking(sock, FALSE);

    /* create local address */
    laddr =
        g_inet_socket_address_new(g_inet_address_new_from_string(local_ip),
                                  53);

    g_debug("bind to local");
    if (!g_socket_bind(sock, laddr, TRUE, &error)) {

        /* bind error */
        g_warning("%s", error->message);
        g_error_free(error);
        error = NULL;
        goto err2;
    }

    g_message("listen to %s:%d", local_ip, 53);
    //g_message("forward to server %s:%d", server_ip, 53);

    g_debug("create server socket address");
    for (i = 0;; i++) {
        GSocketAddress *srvaddr;
        if (servers[i] == NULL) {
            break;
        }
        srvaddr =
            g_inet_socket_address_new(g_inet_address_new_from_string
                                      (servers[i]), 53);
        srvlist = g_list_append(srvlist, srvaddr);
    }

    g_debug("create event source from listen socket");
    esrc = g_socket_create_source(sock, G_IO_IN, NULL);
    g_source_set_callback(esrc, read_from_client, NULL, NULL);

    g_source_attach(esrc, NULL);

    g_source_unref(esrc);
    g_object_unref(sock);

    g_debug("create main loop");
    mloop = g_main_loop_new(NULL, FALSE);

    /* this will run forever */
    g_debug("running...");
    g_main_loop_run(mloop);

    /* clean */
    g_main_loop_unref(mloop);
    //g_source_unref(esrc);
    //g_object_unref(sock);
    g_warning("end");
    return 0;

  err2:
    g_object_unref(sock);
  err1:
    return -1;
}
