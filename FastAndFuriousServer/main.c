#include "Include/faf_server.h"

#define PORT 28876
#define IP_ADDRESS "0.0.0.0"

int main() {
    g_uv_loop = uv_default_loop();

    init_openssl();

    uv_tcp_t server;
    uv_tcp_init(g_uv_loop, &server);

    struct sockaddr_in addr;
    uv_ip4_addr(IP_ADDRESS, PORT, &addr);

    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
    int result = uv_listen((uv_stream_t*)&server, 128, on_new_connection);

    if (result) {
        fprintf(stderr, "ERROR: Listen error %s\n", uv_strerror(result));
        return 1;
    }

    printf("Listening on port %d ...\n", PORT);
    uv_run(g_uv_loop, UV_RUN_DEFAULT);
    return 0;
}
