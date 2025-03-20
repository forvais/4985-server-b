#ifndef UTILS_H
#define UTILS_H

#include <signal.h>

extern volatile sig_atomic_t running;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

void nfree(void **ptr);

void setup_signal(void);

char *strhcpy(char **dst, const char *src);

size_t memcpyds(void *dst, const void *src, size_t static_size, size_t cpybytes);

#endif
