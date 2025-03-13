#include "../include/threads.h"
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

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
