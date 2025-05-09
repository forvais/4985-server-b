#include "database.h"
#include "args.h"
#include "messaging.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#pragma GCC diagnostic ignored "-Waggregate-return"

static ssize_t secure_cmp(const void *a, const void *b, size_t size);
static int     retrieve_int(DBM *db, const char *key, int *result);

static ssize_t secure_cmp(const void *a, const void *b, size_t size)
{
    const uint8_t *x    = (const uint8_t *)a;
    const uint8_t *y    = (const uint8_t *)b;
    uint8_t        diff = 0;

    for(size_t i = 0; i < size; i++)
    {
        diff |= x[i] ^ y[i];    // XOR accumulates differences
    }

    return diff;    // 0 means equal, nonzero means different
}

ssize_t database_open(DBO *dbo, int *err)
{
    dbo->db = dbm_open(dbo->name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if(!dbo->db)
    {
        perror("dbm_open failed");
        *err = errno;
        return -1;
    }
    return 0;
}

int store_string(DBM *db, const char *key, const char *value)
{
    const_datum key_datum   = MAKE_CONST_DATUM(key);
    const_datum value_datum = MAKE_CONST_DATUM(value);

    return dbm_store(db, *(datum *)&key_datum, *(datum *)&value_datum, DBM_REPLACE);
}

int store_int(DBM *db, const char *key, int value)
{
    const_datum key_datum = MAKE_CONST_DATUM(key);
    datum       value_datum;
    int         result;

    value_datum.dptr = (char *)malloc(TO_SIZE_T(sizeof(int)));

    if(value_datum.dptr == NULL)
    {
        return -1;
    }

    memcpy(value_datum.dptr, &value, sizeof(int));
    value_datum.dsize = sizeof(int);

    result = dbm_store(db, *(datum *)&key_datum, value_datum, DBM_REPLACE);

    free(value_datum.dptr);
    return result;
}

int store_byte(DBM *db, const void *key, size_t k_size, const void *value, size_t v_size)
{
    const_datum key_datum   = MAKE_CONST_DATUM_BYTE(key, k_size);
    const_datum value_datum = MAKE_CONST_DATUM_BYTE(value, v_size);

    return dbm_store(db, *(datum *)&key_datum, *(datum *)&value_datum, DBM_REPLACE);
}

char *retrieve_string(DBM *db, const char *key)
{
    const_datum key_datum;
    datum       result;
    char       *retrieved_str;

    key_datum = MAKE_CONST_DATUM(key);

    result = dbm_fetch(db, *(datum *)&key_datum);

    if(result.dptr == NULL)
    {
        return NULL;
    }

    retrieved_str = (char *)malloc(TO_SIZE_T(result.dsize));

    if(!retrieved_str)
    {
        return NULL;
    }

    memcpy(retrieved_str, result.dptr, TO_SIZE_T(result.dsize));

    return retrieved_str;
}

static int retrieve_int(DBM *db, const char *key, int *result)
{
    datum       fetched;
    const_datum key_datum = MAKE_CONST_DATUM(key);

    fetched = dbm_fetch(db, *(datum *)&key_datum);

    if(fetched.dptr == NULL || fetched.dsize != sizeof(int))
    {
        return -1;
    }

    memcpy(result, fetched.dptr, sizeof(int));

    return 0;
}

void *retrieve_byte(DBM *db, const void *key, size_t size)
{
    const_datum key_datum;
    datum       result;
    void       *retrieved;

    key_datum = MAKE_CONST_DATUM_BYTE(key, size);

    result = dbm_fetch(db, *(datum *)&key_datum);

    if(result.dptr == NULL)
    {
        return NULL;
    }

    retrieved = malloc(TO_SIZE_T(result.dsize));

    if(!retrieved)
    {
        return NULL;
    }

    printf("result.dsize: %zu\n", TO_SIZE_T(result.dsize));

    memcpy(retrieved, result.dptr, TO_SIZE_T(result.dsize));

    return retrieved;
}

ssize_t verify_user(DBM *db, const void *key, size_t k_size, const void *value, size_t v_size)
{
    const_datum key_datum;
    datum       result;
    ssize_t     match;

    key_datum = MAKE_CONST_DATUM_BYTE(key, k_size);

    result = dbm_fetch(db, *(datum *)&key_datum);

    if(result.dptr == NULL)
    {
        return -1;
    }

    printf("result.dsize: %zu\n", TO_SIZE_T(result.dsize));

    if(TO_SIZE_T(result.dsize) != v_size)
    {
        return -2;
    }

    match = secure_cmp(result.dptr, value, TO_SIZE_T(result.dsize));

    printf("match: %d\n", (int)match);
    if(match != 0)
    {
        return -3;
    }
    return 0;
}

ssize_t init_pk(DBO *dbo, const char *pk_name)
{
    int err;

    if(database_open(dbo, &err) < 0)
    {
        perror("database error");
        return -1;
    }

    if(retrieve_int(dbo->db, pk_name, &user_index) < 0)
    {
        if(store_int(dbo->db, pk_name, user_index) != 0)
        {
            return -1;
        }
    }

    printf("Retrieved user_count: %d\n", user_index);

    dbm_close(dbo->db);
    return 0;
}
