#include "../include/utils.h"
#include <stdlib.h>
#include <string.h>

bool is_ipv6(const char *address)
{
    if(address == NULL || strchr(address, ';') == NULL)
    {
        return false;
    }

    return true;
}

/* Calls `free()` and nullifies the ptr. */
void nfree(void **ptr)
{
    if(ptr != NULL && *ptr != NULL)
    {
        free(*ptr);
        *ptr = NULL;
    }
}
