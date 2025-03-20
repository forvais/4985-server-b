// cppcheck-suppress-file unusedStructMember

#ifndef DATABASE_H
#define DATABASE_H

#include <ndbm.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __APPLE__
typedef size_t datum_size;
#else
typedef int datum_size;
#endif

#define TO_SIZE_T(x) ((size_t)(x))

typedef struct
{
    const void *dptr;
    datum_size  dsize;
} const_datum;

#define MAKE_CONST_DATUM(str) ((const_datum){(str), (datum_size)strlen(str) + 1})

#define MAKE_CONST_DATUM_BYTE(str, size) ((const_datum){(str), (datum_size)(size)})

#define USER_PK "user_pk"

typedef struct DBO
{
    char *name;
    DBM  *db;
} DBO;

ssize_t database_open(DBO *dbo, int *err);

int store_string(DBM *db, const char *key, const char *value);

int store_int(DBM *db, const char *key, int value);

int store_byte(DBM *db, const void *key, size_t k_size, const void *value, size_t v_size);

char *retrieve_string(DBM *db, const char *key);

int retrieve_int(DBM *db, const char *key, int *result);

void *retrieve_byte(DBM *db, const void *key, size_t size);

ssize_t init_pk(DBO *dbo, const char *pk_name);

int      db_user_insert(DBM *db, const char *username, const char *password);
int      db_user_add_id(DBM *db, const char *username);
uint8_t *db_user_fetch_password(DBM *db, const char *username);
int      db_user_fetch_id(DBM *db, const char *username);
bool     db_user_exists(DBM *db, const char *username);

#endif    // DATABASE_H
