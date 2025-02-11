#include "../include/args.h"
#include "../include/networking.h"
#include <getopt.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_stdlib.h>

#define UNKNOWN_OPTION_MESSAGE_LEN 22

_Noreturn void usage(const char *binary_name, int exit_code, const char *message)
{
    if(message)
    {
        fprintf(stderr, "%s\n\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] -a <address> -p <port>\n", binary_name);
    fputs("Options:\n", stderr);
    fputs("  -h, --help                         Display this help message\n", stderr);
    fputs("  -a <address>, --address <address>  The address of remote server.\n", stderr);
    fputs("  -p <port>,    --port <port>        The server port to use.\n", stderr);
    exit(exit_code);
}

void get_arguments(Arguments *args, int argc, char *argv[])
{
    int opt;
    int err;

    static struct option long_options[] = {
        {"address", required_argument, NULL, 'a'},
        {"port",    required_argument, NULL, 'p'},
        {"help",    no_argument,       NULL, 'h'},
        {NULL,      0,                 NULL, 0  }
    };

    while((opt = getopt_long(argc, argv, "ha:p:", long_options, NULL)) != -1)
    {
        switch(opt)
        {
            case 'a':
                args->addr = optarg;
                break;
            case 'p':
                args->port = convert_port(optarg, &err);

                if(err != 0)
                {
                    usage(argv[0], EXIT_FAILURE, "Port must be between 1 and 65535");
                }
                break;
            case 'h':
                usage(argv[0], EXIT_SUCCESS, NULL);
            case '?':
                if(optopt != 'a' && optopt != 'p')
                {
                    char message[UNKNOWN_OPTION_MESSAGE_LEN];

                    snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                    usage(argv[0], EXIT_FAILURE, message);
                }
                break;
            default:
                usage(argv[0], EXIT_FAILURE, NULL);
        }
    }
}

void validate_arguments(const char *binary_name, const Arguments *args)
{
    if(args->addr == NULL)
    {
        usage(binary_name, EXIT_FAILURE, "You must provide an ipv4 address to connect to.");
    }

    if(args->port == 0)
    {
        usage(binary_name, EXIT_FAILURE, "You must provide an available port to connect to.");
    }
}
