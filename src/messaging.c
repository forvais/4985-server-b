#include "../include/messaging.h"
#include "utils.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

ssize_t copy(int fd_in, int fd_out, size_t size, int *err)
{
    uint8_t *buf;
    ssize_t  retval;
    ssize_t  nread;
    ssize_t  nwrote;

    *err  = 0;
    errno = 0;
    buf   = (uint8_t *)malloc(size);

    if(buf == NULL)
    {
        *err   = errno;
        retval = -1;
        goto done;
    }

    do
    {
        errno = 0;
        nread = read(fd_in, buf, size);

        if(nread < 0)
        {
            *err   = errno;
            retval = -2;
            goto cleanup;
        }

        nwrote = 0;

        do
        {
            ssize_t twrote;
            size_t  remaining;

            remaining = (size_t)(nread - nwrote);
            errno     = 0;
            twrote    = write(fd_out, &buf[nwrote], remaining);

            if(twrote < 0)
            {
                *err   = errno;
                retval = -3;
                goto cleanup;
            }

            nwrote += twrote;
        } while(nwrote != nread);
    } while(nread != 0);

    retval = nwrote;
cleanup:
    nfree((void **)&buf);

done:
    return retval;
}
