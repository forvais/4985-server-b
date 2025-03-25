#include "args.h"
#include "messaging.h"
#include "networking.h"
#include "state.h"
#include "utils.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#define TIMEOUT 3000    // 3s
#define MAX_CLIENTS 1024
#define BACKLOG 5

int main(int argc, char *argv[])
{
    int err;

    args_t      args;
    app_state_t state;

    memset(&args, 0, sizeof(args_t));
    get_arguments(&args, argc, argv);
    validate_arguments(argv[0], &args);

    printf("Server launching... (press Ctrl+C to interrupt)\n");

    // Setup signals
    setup_signal();

    // Setup server state
    app_state_init(&state, MAX_CLIENTS);

    // Start TCP Server
    err          = 0;
    state.sockfd = tcp_server(args.addr, args.port, BACKLOG, &err);
    if(state.sockfd < 0)
    {
        fprintf(stderr, "main::tcp_server: Failed to create TCP server. %d\n", err);
        return EXIT_FAILURE;
    }

    printf("Listening on %s:%d\n", args.addr, args.port);

    // Add server socket to poll list
    app_state_register_client(&state, state.sockfd);

    // Start TCP Client -- Connect to the server manager
    err        = 0;
    state.smfd = tcp_client(args.sm_addr, args.sm_port, &err);
    if(sm_fd < 0)
    {
        fprintf(stderr, "main::tcp_client: Failed to create client socket to the Server Manager.\n");
        return EXIT_FAILURE;
    }

    printf("Connected to server manager at %s:%d\n", args.sm_addr, args.sm_port);

    // Initate the event loop
    err = 0;
    event_loop(&state, TIMEOUT, &err);

    close(state.sockfd);
    close(state.smfd);
    return EXIT_FAILURE;
}
