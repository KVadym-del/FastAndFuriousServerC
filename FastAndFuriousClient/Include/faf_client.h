#ifndef FAF_CLIENT_H
#define FAF_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct faf_client_s faf_client_t;

typedef void (*faf_con_cb)(faf_client_t *client, int status, void *user_data);
typedef void (*faf_msg_cb)(faf_client_t *client, const char *msg, size_t len, void *user_data);
typedef void (*faf_dis_cb)(faf_client_t *client, void *user_data);

/**
 * Creates and initializes a client context.
 * @param ip_addr   Server IP (e.g. "127.0.0.1")
 * @param port      Server Port (e.g. 28876)
 * @param user_data Arbitrary pointer passed back to callbacks (e.g. your GUI handle)
 */
faf_client_t* faf_init(const char *ip_addr, int port, void *user_data);

/**
 * Register callbacks.
 */
void faf_set_callbacks(faf_client_t *ctx, faf_con_cb on_con, faf_msg_cb on_msg, faf_dis_cb on_dis);

/**
 * Connects to the server in a background thread.
 * Returns 0 on success (thread started), non-zero on error.
 */
int faf_connect(faf_client_t *ctx);

/**
 * Queue a message to be sent (Thread-safe).
 */
void faf_send(faf_client_t *ctx, const char *data, size_t len);

/**
 * Stops the thread, closes connections, and frees the context.
 */
void faf_close(faf_client_t *ctx);

#ifdef __cplusplus
}
#endif
#endif // FAF_CLIENT_

#ifdef FAF_CLIENT_IMPLEMENTATION

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/provider.h>

#define FAF_PQC_GROUP "X25519MLKEM768"


typedef struct faf_msg_node_s {
    char *data;
    size_t len;
    struct faf_msg_node_s *next;
} faf_msg_node_t;

struct faf_client_s {
    char ip[64];
    int port;
    void *user_data;

    faf_con_cb cb_connect;
    faf_msg_cb cb_message;
    faf_dis_cb cb_disconnect;

    uv_loop_t *loop;
    uv_thread_t thread;
    uv_tcp_t tcp;
    uv_async_t async_send;
    uv_async_t async_stop;
    int running;

    SSL_CTX *ssl_ctx;
    SSL *ssl;
    BIO *bio_read;
    BIO *bio_write;

    uv_mutex_t queue_lock;
    faf_msg_node_t *q_head;
    faf_msg_node_t *q_tail;
};


static void faf__pump_net(faf_client_t *c) {
    char buf[4096];
    int pending;

    while ((pending = BIO_ctrl_pending(c->bio_write)) > 0) {
        int n = BIO_read(c->bio_write, buf, sizeof(buf));
        if (n <= 0) break;

        uv_buf_t ub = uv_buf_init((char*)malloc(n), n);
        memcpy(ub.base, buf, n);

        uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
        req->data = ub.base;

        uv_write(req, (uv_stream_t*)&c->tcp, &ub, 1,
            (uv_write_cb)(void (*)(uv_write_t*, int))
            (void*)(size_t)(
                 NULL
            ));
    }
}

static void faf__write_cb(uv_write_t *req, int status) {
    if (req->data) free(req->data);
    free(req);
}

static void faf__pump_wrapper(faf_client_t *c) {
    char buf[4096];
    int pending;
    while ((pending = BIO_ctrl_pending(c->bio_write)) > 0) {
        int n = BIO_read(c->bio_write, buf, sizeof(buf));
        if (n <= 0) break;
        char *mem = (char*)malloc(n);
        memcpy(mem, buf, n);
        uv_buf_t ub = uv_buf_init(mem, n);
        uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
        req->data = mem;
        uv_write(req, (uv_stream_t*)&c->tcp, &ub, 1, faf__write_cb);
    }
}

static void faf__on_alloc(uv_handle_t *h, size_t size, uv_buf_t *buf) {
    buf->base = (char*)malloc(size);
    buf->len = (unsigned long)size;
}

static void faf__on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    faf_client_t *c = (faf_client_t*)stream->data;

    if (nread < 0) {
        if (c->cb_disconnect) c->cb_disconnect(c, c->user_data);
        uv_close((uv_handle_t*)stream, NULL);
        if (buf->base) free(buf->base);
        return;
    }

    if (nread > 0) {
        BIO_write(c->bio_read, buf->base, nread);

        char dec[4096];
        int ret;
        do {
            ret = SSL_read(c->ssl, dec, sizeof(dec)-1);
            if (ret > 0) {
                dec[ret] = 0;
                if (c->cb_message) c->cb_message(c, dec, ret, c->user_data);
            }
        } while (ret > 0);

        faf__pump_wrapper(c);
    }

    if (buf->base) free(buf->base);
}

static void faf__on_uv_connect(uv_connect_t *req, int status) {
    faf_client_t *c = (faf_client_t*)req->data;

    if (status < 0) {
        if (c->cb_connect) c->cb_connect(c, status, c->user_data);
        free(req);
        return;
    }

    c->ssl = SSL_new(c->ssl_ctx);
    BIO *bio_internal, *bio_network;
    BIO_new_bio_pair(&bio_internal, 0, &bio_network, 0);

    c->bio_read = bio_network;
    c->bio_write = bio_network;

    SSL_set_bio(c->ssl, bio_internal, bio_internal);
    SSL_set_connect_state(c->ssl);

    c->tcp.data = c;
    uv_read_start((uv_stream_t*)&c->tcp, faf__on_alloc, faf__on_read);

    SSL_do_handshake(c->ssl);
    faf__pump_wrapper(c);

    if (c->cb_connect) c->cb_connect(c, 0, c->user_data);
    free(req);
}

static void faf__async_send_cb(uv_async_t *handle) {
    faf_client_t *c = (faf_client_t*)handle->data;

    uv_mutex_lock(&c->queue_lock);
    faf_msg_node_t *n = c->q_head;
    c->q_head = NULL;
    c->q_tail = NULL;
    uv_mutex_unlock(&c->queue_lock);

    while (n) {
        if (c->ssl) {
            SSL_write(c->ssl, n->data, (int)n->len);
            faf__pump_wrapper(c);
        }
        faf_msg_node_t *next = n->next;
        free(n->data);
        free(n);
        n = next;
    }
}

static void faf__close_handle_cb(uv_handle_t *h) {
}

static void faf__async_stop_cb(uv_async_t *handle) {
    faf_client_t *c = (faf_client_t*)handle->data;

    if (!uv_is_closing((uv_handle_t*)&c->tcp)) uv_close((uv_handle_t*)&c->tcp, faf__close_handle_cb);
    uv_close((uv_handle_t*)&c->async_send, faf__close_handle_cb);
    uv_close((uv_handle_t*)&c->async_stop, faf__close_handle_cb); // Self close

    uv_stop(c->loop);
}

static void faf__thread_entry(void *arg) {
    faf_client_t *c = (faf_client_t*)arg;
    c->loop = uv_loop_new();

    uv_tcp_init(c->loop, &c->tcp);

    uv_async_init(c->loop, &c->async_send, faf__async_send_cb);
    c->async_send.data = c;

    uv_async_init(c->loop, &c->async_stop, faf__async_stop_cb);
    c->async_stop.data = c;

    struct sockaddr_in dest;
    uv_ip4_addr(c->ip, c->port, &dest);

    uv_connect_t *req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    req->data = c;
    uv_tcp_connect(req, &c->tcp, (const struct sockaddr*)&dest, faf__on_uv_connect);

    uv_run(c->loop, UV_RUN_DEFAULT);

    uv_loop_delete(c->loop);
    c->loop = NULL;
}

faf_client_t* faf_init(const char *ip_addr, int port, void *user_data) {
    OSSL_PROVIDER_load(NULL, "default");

    faf_client_t *c = (faf_client_t*)calloc(1, sizeof(faf_client_t));
    #ifdef _WIN32
        strncpy_s(c->ip, sizeof(c->ip), ip_addr, 63);
    #else
        strncpy(c->ip, ip_addr, 63);
    #endif
    c->port = port;
    c->user_data = user_data;
    uv_mutex_init(&c->queue_lock);

    c->ssl_ctx = SSL_CTX_new(TLS_client_method());

    if (!SSL_CTX_set1_groups_list(c->ssl_ctx, FAF_PQC_GROUP)) {
        free(c);
        return NULL;
    }

    SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_NONE, NULL);

    return c;
}

void faf_set_callbacks(faf_client_t *ctx, faf_con_cb on_con, faf_msg_cb on_msg, faf_dis_cb on_dis) {
    ctx->cb_connect = on_con;
    ctx->cb_message = on_msg;
    ctx->cb_disconnect = on_dis;
}

int faf_connect(faf_client_t *ctx) {
    if (ctx->running) return -1;
    ctx->running = 1;
    return uv_thread_create(&ctx->thread, faf__thread_entry, ctx);
}

void faf_send(faf_client_t *ctx, const char *data, size_t len) {
    if (!ctx->running) return;

    faf_msg_node_t *n = (faf_msg_node_t*)malloc(sizeof(faf_msg_node_t));
    n->data = (char*)malloc(len);
    memcpy(n->data, data, len);
    n->len = len;
    n->next = NULL;

    uv_mutex_lock(&ctx->queue_lock);
    if (ctx->q_tail) {
        ctx->q_tail->next = n;
        ctx->q_tail = n;
    } else {
        ctx->q_head = n;
        ctx->q_tail = n;
    }
    uv_mutex_unlock(&ctx->queue_lock);

    uv_async_send(&ctx->async_send);
}

void faf_close(faf_client_t *ctx) {
    if (ctx->running) {
        uv_async_send(&ctx->async_stop);
        uv_thread_join(&ctx->thread);
        ctx->running = 0;
    }

    if (ctx->ssl) SSL_free(ctx->ssl);
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    uv_mutex_destroy(&ctx->queue_lock);
    free(ctx);
}

#endif // FAF_CLIENT_IMPLEMENTATION
