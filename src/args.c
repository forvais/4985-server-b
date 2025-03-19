#include "args.h"
#include "networking.h"
#include <getopt.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_stdlib.h>

#define INADDRESS "0.0.0.0"
#define OUTADDRESS "127.0.0.1"
#define PORT "8081"
#define SM_PORT "8082" /* Default Server->SM listening port */
#define UNKNOWN_OPTION_MESSAGE_LEN 22

_Noreturn void usage(const char *binary_name, int exit_code, const char *message)
{
    if(message)
    {
        fprintf(stderr, "%s\n\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] -a <address> -p <port>\n", binary_name);
    fputs("Options:\n", stderr);
    fputs("  -h, --help                            Display this help message\n", stderr);
    fputs("  -a <address>, --address <address>     The address of the server.\n", stderr);
    fputs("  -p <port>,    --port <port>           The server port to use.\n", stderr);
    fputs("  -A <address>, --sm_address <address>  The address of server manager.\n", stderr);
    fputs("  -P <port>,    --sm_port <port>        The server manager port.\n", stderr);
    exit(exit_code);
}

void get_arguments(args_t *args, int argc, char *argv[])
{
    int opt;

    static struct option long_options[] = {
        {"address",    optional_argument, NULL, 'a'},
        {"port",       optional_argument, NULL, 'p'},
        {"sm_address", optional_argument, NULL, 'A'},
        {"sm_port",    optional_argument, NULL, 'P'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,         0,                 NULL, 0  }
    };

    while((opt = getopt_long(argc, argv, "ha:p:A:P:", long_options, NULL)) != -1)
    {
        switch(opt)
        {
            case 'a':
                args->addr = optarg;
                break;
            case 'p':
                if(convert_port(optarg, &args->port) != 0)
                {
                    usage(argv[0], EXIT_FAILURE, "Port must be between 1 and 65535");
                }
                break;
            case 'A':
                args->sm_addr = optarg;
                break;
            case 'P':
                if(convert_port(optarg, &args->sm_port) != 0)
                {
                    usage(argv[0], EXIT_FAILURE, "Port must be between 1 and 65535");
                }
                break;
            case 'h':
                usage(argv[0], EXIT_SUCCESS, NULL);
            case '?':
                if(optopt != 'a' && optopt != 'p' && optopt != 'A' && optopt != 'P')
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

void validate_arguments(const char *binary_name, args_t *args)
{
    (void)(binary_name);    // Reserved for later use for options that do not have default values and
                            // consequently need to print the help menu.

    if(args->addr == NULL)
    {
        args->addr = INADDRESS;
    }

    if(args->port == 0)
    {
        convert_port(PORT, &args->port);
    }

    if(args->sm_addr == NULL)
    {
        args->sm_addr = OUTADDRESS;
    }

    if(args->sm_port == 0)
    {
        convert_port(SM_PORT, &args->sm_port);
    }
}
