#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__) && defined(__clang__)
_Pragma("clang diagnostic ignored \"-Wdisabled-macro-expansion\"")
#endif

#define SIG_BUF 50

    volatile sig_atomic_t running = 1;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

/* Calls `free()` and nullifies the ptr. */
void nfree(void **ptr)
{
    if(ptr != NULL && *ptr != NULL)
    {
        free(*ptr);
        *ptr = NULL;
    }
}

static void handle_signal(int sig)
{
    char message[SIG_BUF];

    snprintf(message, sizeof(message), "Caught signal: %d (%s)\n", sig, strsignal(sig));
    write(STDOUT_FILENO, message, strlen(message));

    if(sig == SIGINT)
    {
        running = 0;
        snprintf(message, sizeof(message), "\n%s\n", "Shutting down gracefully...");
    }
    write(STDOUT_FILENO, message, strlen(message));
}

void setup_signal(void)
{
    struct sigaction sa;

    sa.sa_handler = handle_signal;    // Set handler function for SIGINT
    sigemptyset(&sa.sa_mask);         // Don't block any additional signals
    sa.sa_flags = 0;

    // Register signal handler
    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

/* Writes a string to a heap-allocated buffer. */
char *strhcpy(char **dst, const char *src)
{
    // Get string length
    const size_t len = strlen(src);

    // Calloc buffer
    errno = 0;
    *dst  = (char *)calloc(len + 1, sizeof(char));
    if(*dst == NULL)
    {
        return NULL;
    }

    // Copy str to buffer
    memcpy(*dst, src, len);

    return *dst;
}

/* Copies memory from a [d]ynamic buffer to a [s]tatic buffer  */
size_t memcpyds(void *dst, const void *src, size_t static_size, size_t cpybytes)
{
    size_t max_bytes;

    if(dst == NULL || src == NULL || static_size == 0 || cpybytes == 0)
    {
        errno = EINVAL;
        return 0;
    }

    max_bytes = (cpybytes >= static_size) ? static_size : cpybytes;

    memcpy(dst, src, max_bytes);

    return max_bytes;
}
