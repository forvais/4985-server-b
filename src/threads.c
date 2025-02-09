#include "threads.h"
#include "../include/messaging.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define BUFLEN 1024

int start_thread(void *(*thread_fn)(void *targs), void *targs, size_t opts)
{
    pthread_t thread;

    if(thread_fn == NULL)
    {
        return -1;
    }

    errno = pthread_create(&thread, NULL, thread_fn, targs);
    if(errno != 0)
    {
        perror("start_thread::pthread_create");
        return -2;
    }

    if(opts & O_THREAD_JOIN)
    {
        errno = pthread_join(thread, NULL);
        if(errno != 0)
        {
            perror("start_thread::pthread_join");
            return -3;
        }
    }

    return 0;
}

void *thread_echo(void *targs)
{
    int err;

    const thread_args *args;
    int                connfd;

    args   = (thread_args *)targs;
    connfd = args->connfd;

    err = 0;
    if(copy(connfd, connfd, BUFLEN, &err) < 0)
    {
        errno = err;
        perror("thread_echo::copy");
        goto cleanup;
    }

cleanup:
    close(connfd);
    return NULL;
}
