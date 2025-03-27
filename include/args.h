// cppcheck-suppress-file unusedStructMember

#ifndef ARGS_H
#define ARGS_H

#include <arpa/inet.h>
#include <unistd.h>
#define BUF_SIZE 50
#define ARGC 10

// 1 = Verbose, 2 = Debug
extern int verbose;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

typedef struct args_t
{
    const char *addr;
    in_port_t   port;
    const char *sm_addr;
    in_port_t   sm_port;
    int        *sm_fd;
    int        *err;
    char        buf[BUF_SIZE];
    char       *argv[2];
    char       *envp[ARGC];
} args_t;

_Noreturn void usage(const char *binary_name, int exit_code, const char *message);

void get_arguments(args_t *args, int argc, char *argv[]);

#endif    // ARGS_H
