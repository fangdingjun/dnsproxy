#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <arpa/inet.h>

gchar *servers[] = {
    "8.8.8.8",
    "4.2.2.2",
    "114.114.114.114",
    NULL,
};

GList *srvlist = NULL;
struct thread_arg {
    GString *req;
    GSocketAddress *addr;
};

GThreadPool *pool;

gboolean read_from_client(gpointer data);

void do_dns_forward_tcp(gpointer data, gpointer user_data)
{
    struct thread_arg *r;
    GString *req;
    GSocketAddress *caddr;
    GSocket *sock;
    //GSocketAddress *saddr;
    //GSocketAddress *addr;
    GSocket *lsock;
    GError *error = NULL;
    //GList *tmp;
    //gint fd;
    fd_set rfds, wfds;
    gint ret;
    struct timeval tv1;
    //gint retry_times = 0;
    gint nbytes;
    gchar buf[512];
    gint i;
    gint max_fd = 0;
    GList *socklist = NULL;
    GList *sl = NULL;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    lsock = (GSocket *) user_data;
    r = (struct thread_arg *) data;
    req = r->req;
    caddr = r->addr;

    for (sl = srvlist; sl && sl != sl->next; sl = sl->next) {
        sock = g_socket_new(G_SOCKET_FAMILY_IPV4,
                            G_SOCKET_TYPE_STREAM,
                            G_SOCKET_PROTOCOL_TCP, &error);
        g_socket_set_blocking(sock, FALSE);
        if (!g_socket_connect
            (sock, (GSocketAddress *) sl->data, NULL, &error)) {
            if (error->code != G_IO_ERROR_PENDING) {
                g_print("%s\n", error->message);
                goto err2;
            }
            g_error_free(error);
            error = NULL;
        }
        socklist = g_list_append(socklist, sock);
    }

    // wait socket ready
    tv1.tv_sec = 0;
    tv1.tv_usec = 600;
    select(0, NULL, NULL, NULL, &tv1);

    for (sl = socklist; sl && sl != sl->next; sl = sl->next) {
        gint fd;
        fd = g_socket_get_fd((GSocket *) sl->data);
        FD_SET(fd, &wfds);
        max_fd = MAX(max_fd, fd);
    }

    tv1.tv_sec = 2;
    tv1.tv_usec = 0;
    ret = select(max_fd + 1, NULL, &wfds, NULL, &tv1);
    // send msg
    if (ret > 0) {

        for (sl = socklist; sl && sl != sl->next; sl = sl->next) {
            gchar *buf_s;
            gint fd;
            GSocket *s1;
            buf_s = g_malloc(req->len + 2);
            *((guint16 *) buf_s) = htons(req->len);
            memcpy(buf_s + 2, req->str, req->len);
            fd = g_socket_get_fd((GSocket *) sl->data);
            s1 = (GSocket *) sl->data;
            if (FD_ISSET(fd, &wfds)) {
                if (!g_socket_check_connect_result(s1, &error)) {
                    g_print("%s\n", error->message);
                    g_error_free(error);
                    error = NULL;
                    continue;
                }
                g_print("send to server\n");
                g_socket_send(s1, buf_s, req->len + 2, NULL, NULL);
            }
        }
    } else if (ret < 0) {       // error
        goto err2;
    } else {                    // timeout
        goto err2;
    }

    // receive data
    for (i = 0; i < 3; i++) {
        FD_ZERO(&rfds);
        max_fd = 0;
        for (sl = socklist; sl && sl != sl->next; sl = sl->next) {
            gint fd;
            fd = g_socket_get_fd((GSocket *) sl->data);
            FD_SET(fd, &rfds);
            max_fd = MAX(max_fd, fd);
        }
        int ret1;
        tv1.tv_sec = 2;
        tv1.tv_usec = 0;
        ret1 = select(max_fd + 1, &rfds, NULL, NULL, &tv1);
        if (ret1) {
            for (sl = socklist; sl && sl != sl->next; sl = sl->next) {
                gint fd;
                GSocket *t1;
                t1 = (GSocket *) sl->data;
                fd = g_socket_get_fd((GSocket *) sl->data);
                if (FD_ISSET(fd, &rfds)) {
                    g_print("receive from server\n");
                    if ((nbytes =
                         g_socket_receive(t1, buf, 512, NULL,
                                          &error)) == -1) {
                        g_print("%s\n", error->message);
                        g_error_free(error);
                        continue;
                    }
                    g_socket_send_to(lsock, caddr, buf + 2, nbytes - 2,
                                     NULL, NULL);
                }
            }
        }
    }
  err2:
    for (sl = socklist; sl && sl != sl->next; sl = sl->next) {
        g_object_unref((GSocketAddress *) sl->data);
    }
    //err1:
    g_string_free(req, TRUE);
    g_free(r);
    return;
}

void do_dns_forward(gpointer data, gpointer user_data)
{
    struct thread_arg *r;
    GString *req;
    GSocketAddress *caddr;
    GSocket *sock;
    GSocketAddress *saddr;
    GSocketAddress *addr;
    GSocket *lsock;
    GError *error = NULL;
    GList *tmp;
    gint fd;
    fd_set rfds;
    gint ret;
    struct timeval tv1;
    gint retry_times = 0;
    gint nbytes;
    gchar buf[512];
    gint i;

    lsock = (GSocket *) user_data;
    r = (struct thread_arg *) data;
    req = r->req;
    caddr = r->addr;

    //g_print("enter dns forward\n");
    sock = g_socket_new(G_SOCKET_FAMILY_IPV4,
                        G_SOCKET_TYPE_DATAGRAM,
                        G_SOCKET_PROTOCOL_UDP, &error);
    if (sock == NULL) {
        g_print("%s\n", error->message);
        g_error_free(error);
        error = NULL;
        goto err1;
    }
    /*
       saddr=g_inet_socket_address_new(
       g_inet_address_new_from_string("8.8.8.8"),
       53);
     */
  retry:
    //g_print("send to server\n");
    for (tmp = srvlist; tmp && tmp != tmp->next; tmp = tmp->next) {
        saddr = (GSocketAddress *) tmp->data;
        if (g_socket_send_to(sock, saddr, req->str, req->len, NULL, &error)
            == -1) {
            g_print("%s\n", error->message);
            goto err3;
        }
    }

    g_socket_set_blocking(sock, FALSE);

    fd = g_socket_get_fd(sock);

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv1.tv_sec = 2;
    tv1.tv_usec = 0;
    ret = select(fd + 1, &rfds, NULL, NULL, &tv1);
    if (ret < 0) {
        g_print("select failed\n");
        goto err3;
    } else if (ret == 0) {
        retry_times++;
        if (retry_times < 3) {
            g_print("timeout, retrying...\n");
            goto retry;
        } else {
            goto err3;
        }
    }
    for (i = 0; i < 3; i++) {
        addr = NULL;
        //g_print("receive from server\n");
        if ((nbytes =
             g_socket_receive_from(sock, &addr, buf, 512, NULL,
                                   &error)) == -1) {
            if (error->code == G_IO_ERROR_WOULD_BLOCK) {
                g_error_free(error);
                error = NULL;
                continue;
            }
            g_print("%s\n", error->message);
            g_error_free(error);
            goto err3;
        }
        g_print("receive %d bytes from %s:%d\n", nbytes,
                g_inet_address_to_string(g_inet_socket_address_get_address
                                         ((GInetSocketAddress *) addr)),
                g_inet_socket_address_get_port((GInetSocketAddress *)
                                               addr));
        //g_print("send to client\n");
        if (g_socket_send_to(lsock, caddr, buf, nbytes, NULL, &error) ==
            -1) {
            g_print("%s\n", error->message);
            g_error_free(error);
            error = NULL;
        }
    }

    //g_print("free mem\n");
  err3:
    //g_print("free server addr\n");
    //g_free(saddr);
    //err2:
    //g_print("close socket\n");
    g_object_unref(sock);
  err1:
    //g_print("free buf\n");
    g_string_free(req, TRUE);
    //g_print("free thread_arg\n");
    g_free(r);
    return;
}

gboolean read_data(GIOChannel * src, GIOCondition cond, gpointer data)
{
    //g_print("enter read_data\n");
    if (cond == G_IO_IN) {
        return read_from_client(data);
    }
    return TRUE;
}

gboolean read_from_client(gpointer data)
{
    GSocket *sock1;
    GError *error = NULL;
    GSocketAddress *addr = NULL;
    gchar buf[512];
    gssize nbytes;
    gboolean ret = TRUE;
    sock1 = (GSocket *) data;
    //g_print("enter callback\n");
    if (!data) {
        g_print("data is NULL\n");
        return TRUE;
    }

    while (1) {
        //g_print("begin to read\n");
        addr = NULL;
        error = NULL;
        if ((nbytes =
             g_socket_receive_from(sock1, &addr, buf, 512, NULL,
                                   &error)) == -1) {
            if (error->code == G_IO_ERROR_WOULD_BLOCK) {
                //g_print("read again\n");
                break;
            }
            g_print("read socket error: %s\n", error->message);
            ret = FALSE;
            break;
        }
        g_print("read %d bytes from %s:%d\n", nbytes,
                g_inet_address_to_string(g_inet_socket_address_get_address
                                         ((GInetSocketAddress *) addr)),
                g_inet_socket_address_get_port((GInetSocketAddress *) addr)
            );
        GString *r = g_string_new_len(buf, nbytes);
        struct thread_arg *d = g_new0(struct thread_arg, 1);
        d->req = r;
        d->addr = addr;
        /*
        if (!g_thread_pool_push(pool, d, &error)) {
            g_print("%s\n", error->message);
            break;
        }*/
        g_thread_pool_push(pool, d, &error);
    }
    return ret;

}

int main(int argc, char *argv[])
{
    GSocketAddress *local;
    GSocket *sock;
    GError *error = NULL;
    GMainContext *mcontext;
    GMainLoop *mloop;
    GIOChannel *chl1;
    //GIOChannel *chl2;
    //GSource *src1;
    GSocketAddress *saddr;
    gint i;


    int ret = 0;

    g_type_init();

    // create server socketaddress struct
    for (i = 0;; i++) {
        if (servers[i] == NULL) {
            break;
        }
        saddr =
            g_inet_socket_address_new(g_inet_address_new_from_string
                                      (servers[i]), 53);
        srvlist = g_list_append(srvlist, saddr);
    }
    local =
        g_inet_socket_address_new(g_inet_address_new_from_string
                                  ("0.0.0.0"), 53);
    sock =
        g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
                     G_SOCKET_PROTOCOL_UDP, &error);
    if (sock == NULL) {
        g_print("create sock failed: %s\n", error->message);
        g_error_free(error);
        error = NULL;
        ret = -1;
        goto err1;
    }
    g_print("socket create success\n");
    g_print("set to nonblock\n");
    g_socket_set_blocking(sock, FALSE);
    g_print("begin to bind\n");
    if (!g_socket_bind(sock, local, TRUE, &error)) {
        g_print("bind failed: %s\n", error->message);
        g_error_free(error);
        error = NULL;
        ret = -1;
        goto err2;
    }
    g_print("bind success\n");

    pool = g_thread_pool_new(do_dns_forward_tcp, sock, 4, FALSE, &error);
    mcontext = g_main_context_new();

    chl1 = g_io_channel_unix_new(g_socket_get_fd(sock));
    g_io_add_watch(chl1, G_IO_IN, read_data, sock);
    //src1=g_io_create_watch(chl1,G_IO_IN);
    //g_source_set_callback(src1,read_from_client,sock,NULL);
    //g_source_attach(src1,mcontext);

    mloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mloop);

//err5:
    //g_source_unref(src1);
//err4:
    g_io_channel_unref(chl1);
//err3:
    g_main_loop_unref(mloop);
    g_main_context_unref(mcontext);

  err2:
    g_object_unref(sock);
  err1:
    return ret;

}
