#include "../include/database.h"
#include <errno.h>
#include <fcntl.h>
#include <ndbm.h>
#include <p101_c/p101_stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#pragma GCC diagnostic ignored "-Waggregate-return"

ssize_t database_connect(int *err)
{
    DBM        *db;
    datum       key;
    datum       value;
    datum       result;
    const char *name   = "name";
    const char *nvalue = "Tia";
    void       *ptr;
    const char  filename[] = "mydb";
    char        filename_mutable[sizeof(filename)];
    memcpy(filename_mutable, filename, sizeof(filename));

    ptr = malloc(strlen(name) + 1);
    if(ptr == NULL)
    {
        perror("malloc error");
        *err = errno;
        return -1;
    }
    key.dptr = (char *)ptr;

    ptr = malloc(strlen(nvalue) + 1);
    if(ptr == NULL)
    {
        perror("malloc error");
        *err = errno;
        free(key.dptr);
        return -1;
    }
    value.dptr = (char *)ptr;

    ptr = malloc(strlen(name) + strlen(nvalue) + 1);
    if(ptr == NULL)
    {
        perror("malloc error");
        *err = errno;
        free(key.dptr);
        free(value.dptr);
        return -1;
    }
    result.dptr = (char *)ptr;

    db = dbm_open(filename_mutable, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if(!db)
    {
        perror("dbm_open failed");
        *err = errno;
        free(key.dptr);
        free(value.dptr);
        free(ptr);
        return -1;
    }

    memcpy(key.dptr, name, strlen(name) + 1);
    key.dsize = (int)strlen(key.dptr) + 1;

    memcpy(value.dptr, nvalue, strlen(nvalue) + 1);
    value.dsize = (int)strlen(value.dptr) + 1;

    dbm_store(db, key, value, DBM_REPLACE);

    result = dbm_fetch(db, key);
    if(result.dptr)
    {
        printf("Fetched value: %s\n", result.dptr);
    }

    dbm_close(db);

    free(key.dptr);
    free(value.dptr);
    free(ptr);

    return 0;
}
