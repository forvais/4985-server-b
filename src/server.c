#include "args.h"
#include "messaging.h"
#include "networking.h"
#include "utils.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#define BACKLOG 5

int main(int argc, char *argv[])
{
    int    server_fd;
    int    sm_fd;
    args_t args;
    int    err;

    err = 0;

    memset(&args, 0, sizeof(args_t));
    get_arguments(&args, argc, argv);
    validate_arguments(argv[0], &args);

    printf("Server launching... (press Ctrl+C to interrupt)\n");

    // Setup signals
    setup_signal();

    // Start TCP Server
    server_fd = tcp_server(args.addr, args.port, BACKLOG, &err);
    if(server_fd < 0)
    {
        fprintf(stderr, "main::tcp_server: Failed to create TCP server. %d\n", err);
        return EXIT_FAILURE;
    }

    printf("Listening on %s:%d\n", args.addr, args.port);

    // Start TCP Client -- Connect to the server manager
    sm_fd = tcp_client(args.sm_addr, args.sm_port, &err);
    if(sm_fd < 0)
    {
        fprintf(stderr, "main::tcp_client: Failed to create client socket to the Server Manager.\n");
        return EXIT_FAILURE;
    }

    printf("Connected to server manager at %s:%d\n", args.sm_addr, args.sm_port);

    // Wait for client connections
    err = 0;
    event_loop(server_fd, sm_fd, &err);

    close(sm_fd);
    close(server_fd);
    return EXIT_FAILURE;
}
