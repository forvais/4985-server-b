#include "../include/args.h"
#include "../include/messaging.h"
#include "../include/networking.h"
#include <errno.h>
#include <memory.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__) && defined(__clang__)
_Pragma("clang diagnostic ignored \"-Wdisabled-macro-expansion\"")
#endif

#define INADDRESS "0.0.0.0"
#define PORT "8081"
#define SIG_BUF 50

    static volatile sig_atomic_t running;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

static const char *const ending = "\nShutting down gracefully...\n";

static void handle_signal(int sig)
{
    char message[SIG_BUF];

    snprintf(message, sizeof(message), "Caught signal: %d (%s)\n", sig, strsignal(sig));
    write(STDOUT_FILENO, message, strlen(message));

    if(sig == SIGINT)
    {
        running = 0;
        snprintf(message, sizeof(message), "%s\n", ending);
    }
    write(STDOUT_FILENO, message, strlen(message));
}

static int request_handler(int connfd)
{
    int retval;
    int err;

    header_t header;
    uint8_t *buf;

    err = 0;

    if(read_packet(connfd, &buf, &header, &err) < 0)
    {
        errno = err;
        perror("request_handler::read_fd_until_eof");
    }

    //Acknowledgement response
    header_t response_header = {
        .type = 0x01,
        .version = header.version,
        .sender_id = header.sender_id,
        .payload_len = 8  // Sending "Received"
    };

    uint8_t response_payload[] = "Received";
    send_packet(connfd, &response_header, response_payload);

    free(buf);

    retval = EXIT_SUCCESS;
    return retval;
}

int main(int argc, char *argv[])
{
    int retval;

    struct sigaction sa;
    pid_t            pid;
    int              sockfd;
    Arguments        args;
    int              err;

    sa.sa_handler = handle_signal;    // Set handler function for SIGINT
    sigemptyset(&sa.sa_mask);         // Don't block any additional signals
    sa.sa_flags = 0;

    // Register signal handler
    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    printf("Server launching... (press Ctrl+C to interrupt)\n");

    memset(&args, 0, sizeof(Arguments));
    args.addr = INADDRESS;
    args.port = convert_port(PORT, &err);

    get_arguments(&args, argc, argv);
    validate_arguments(argv[0], &args);

    printf("Listening on %s:%d\n", args.addr, args.port);

    retval = EXIT_SUCCESS;

    // Start TCP Server
    sockfd = tcp_server(&args);
    if(sockfd < 0)
    {
        fprintf(stderr, "main::tcp_server: Failed to create TCP server.\n");
        return EXIT_FAILURE;
    }

    // Wait for client connections
    err     = 0;
    running = 1;
    while(running)
    {
        int                connfd;
        struct sockaddr_in connaddr;
        socklen_t          connsize;

        // !!BLOCKING!! Get client connection
        connsize = sizeof(struct sockaddr_in);
        memset(&connaddr, 0, connsize);

        errno  = 0;
        connfd = accept(sockfd, (struct sockaddr *)&connaddr, &connsize);
        if(connfd < 0)
        {
            // perror("main::accept");
            continue;
        }

        printf("New connection from: %s:%d\n", inet_ntoa(connaddr.sin_addr), connaddr.sin_port);

        // Fork the process
        errno = 0;
        pid   = fork();
        if(pid < 0)
        {
            perror("main::fork");
            close(connfd);
            continue;
        }

        if(pid == 0)
        {
            retval = request_handler(connfd);
            close(connfd);
            goto exit;
        }

        close(connfd);
    }

exit:
    close(sockfd);
    return retval;
}
