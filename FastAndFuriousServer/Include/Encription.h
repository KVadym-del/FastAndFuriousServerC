#ifndef FAF_SERVER_ENC_H
#define FAF_SERVER_ENC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <uv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#define CERT_FILE "server.crt"
#define KEY_FILE  "server.key"
#define PQC_GROUP "X25519MLKEM768"

typedef struct {
    uv_tcp_t handle;
    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;
} client_ctx_t;

uv_loop_t *g_uv_loop = NULL;
SSL_CTX *g_ssl_ctx = NULL;

void generate_self_signed_cert() {
    printf("Generating new self-signed certificate and key...\n");

    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating RSA key\n");
        exit(1);
    }
    EVP_PKEY_CTX_free(pctx);

    x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing certificate\n");
        exit(1);
    }

    BIO *bio_key = BIO_new_file(KEY_FILE, "w");
    if (!bio_key) {
        fprintf(stderr, "Error writing to %s\n", KEY_FILE);
        exit(1);
    }
    if (!PEM_write_bio_PrivateKey(bio_key, pkey, NULL, NULL, 0, NULL, NULL)) {
         fprintf(stderr, "Error exporting private key\n");
         exit(1);
    }
    BIO_free(bio_key);

    BIO *bio_crt = BIO_new_file(CERT_FILE, "w");
    if (!bio_crt) {
        fprintf(stderr, "Error writing to %s\n", CERT_FILE);
        exit(1);
    }
    if (!PEM_write_bio_X509(bio_crt, x509)) {
         fprintf(stderr, "Error exporting certificate\n");
         exit(1);
    }
    BIO_free(bio_crt);

    EVP_PKEY_free(pkey);
    X509_free(x509);

    printf("Successfully generated %s and %s\n", CERT_FILE, KEY_FILE);
}

void ensure_certificates_exist() {
    if (access(CERT_FILE, F_OK) != 0 || access(KEY_FILE, F_OK) != 0) {
        generate_self_signed_cert();
    }
}

void c_uv_write(uv_write_t* req, int status)
{
    free(req->data);
    free(req);
}

void pump_ssl_to_socket(client_ctx_t *client) {
    char buf[4096];
    int pending;

    while ((pending = BIO_ctrl_pending(client->write_bio)) > 0) {
        int bytes_read = BIO_read(client->write_bio, buf, sizeof(buf));
        if (bytes_read <= 0) break;

        uv_buf_t uvbuf = uv_buf_init(malloc(bytes_read), bytes_read);
        memcpy(uvbuf.base, buf, bytes_read);

        uv_write_t *req = malloc(sizeof(uv_write_t));
        req->data = uvbuf.base;

        uv_write(req, (uv_stream_t*)&client->handle, &uvbuf, 1, c_uv_write);
    }
}

void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_ctx_t *client = (client_ctx_t*)stream;

    if (nread < 0) {
        if (nread != UV_EOF) fprintf(stderr, "Read error: %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*)stream, (uv_close_cb)free);
        SSL_free(client->ssl);
        free(buf->base);
        return;
    }

    if (nread > 0) {
        BIO_write(client->read_bio, buf->base, nread);

        char decrypt_buf[4096];
        int ssl_ret;

        do {
            ssl_ret = SSL_read(client->ssl, decrypt_buf, sizeof(decrypt_buf) - 1);
            if (ssl_ret > 0) {
                decrypt_buf[ssl_ret] = '\0';
                printf("[App] Received: %s\n", decrypt_buf);
                // ECHO Back
                SSL_write(client->ssl, decrypt_buf, ssl_ret);
            }
        } while (ssl_ret > 0);

        pump_ssl_to_socket(client);
    }

    free(buf->base);
}

void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

void on_new_connection(uv_stream_t *server, int status) {
    if (status < 0) return;

    client_ctx_t *client = malloc(sizeof(client_ctx_t));
    uv_tcp_init(g_uv_loop, &client->handle);

    if (uv_accept(server, (uv_stream_t*)&client->handle) == 0) {
        client->ssl = SSL_new(g_ssl_ctx);
        BIO *internal_bio, *network_bio;
        BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0);

        client->read_bio = network_bio;
        client->write_bio = network_bio;

        SSL_set_bio(client->ssl, internal_bio, internal_bio);
        SSL_set_accept_state(client->ssl);

        uv_read_start((uv_stream_t*)&client->handle, on_alloc, on_read);
        pump_ssl_to_socket(client);
    } else {
        free(client);
    }
}

void init_openssl() {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) {
        fprintf(stderr, "Fatal: Failed to load default provider.\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    g_ssl_ctx = SSL_CTX_new(TLS_server_method());

    if (!SSL_CTX_set1_groups_list(g_ssl_ctx, PQC_GROUP)) {
        fprintf(stderr, "ERROR: Failed to set group %s.\n", PQC_GROUP);
        fprintf(stderr, "Possibilities:\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    ensure_certificates_exist();

    if (SSL_CTX_use_certificate_file(g_ssl_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(g_ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "ERROR: failed to load certs.\n");
        exit(1);
    }
}



#endif // FAF_SERVER_ENC_H
