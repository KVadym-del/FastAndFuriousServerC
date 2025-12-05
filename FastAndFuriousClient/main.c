#include <stdio.h>
#include <string.h>

#define FAF_CLIENT_IMPLEMENTATION
#include "Include/faf_client.h"

void app_on_connect(faf_client_t *client, int status, void *user_data) {
    if (status == 0) {
        printf("[GUI Event] Connected to %s!\n", (char*)user_data);
    } else {
        printf("[GUI Event] Connection failed.\n");
    }
}

void app_on_msg(faf_client_t *client, const char *msg, size_t len, void *user_data) {
    printf("[GUI Event] Server says: %s\n", msg);
}

void app_on_disconnect(faf_client_t *client, void *user_data) {
    printf("[GUI Event] Disconnected.\n");
}

int main() {
    const char *my_app_name = "FastAndFuriousClient";

    faf_client_t *cli = faf_init("127.0.0.1", 28876, (void*)my_app_name);

    faf_set_callbacks(cli, app_on_connect, app_on_msg, app_on_disconnect);

    printf("Connecting...\n");
    faf_connect(cli);

    char buf[100];
    while(1) {
        printf("> ");
        if (!fgets(buf, sizeof(buf), stdin)) break;
        if (strncmp(buf, "quit", 4) == 0) break;

        buf[strcspn(buf, "\n")] = 0;

        faf_send(cli, buf, strlen(buf));
    }

    printf("Closing...\n");
    faf_close(cli);
    return 0;
}
