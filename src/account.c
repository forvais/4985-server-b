#include "account.h"
#include "database.h"
#include "packets.h"
#include "serializers.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_stdlib.h>
#include <string.h>

const funcMapping acc_func[] = {
    {ACC_Create,  account_create},
    {ACC_Login,   account_login },
    {ACC_Logout,  account_logout},
    {ACC_Edit,    NULL          },
    {SYS_Success, NULL          }  // Null termination for safety
};

ssize_t account_create(context_t *ctx)
{
    packet_acc_create_t  packet_acc_create;
    packet_sys_success_t packet_sys_success;

    DBO  userDB;
    DBO  index_userDB;
    char user_name[]  = "users";
    char index_name[] = "index_user";

    int user_id;

    userDB.name       = user_name;
    userDB.db         = NULL;
    index_userDB.name = index_name;
    index_userDB.db   = NULL;

    printf("in account_create %d \n", ctx->client_fd);

    if(database_open(&userDB, &ctx->err) < 0)
    {
        perror("database error");
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }

    if(database_open(&index_userDB, &ctx->err) < 0)
    {
        perror("database error");
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }

    // Deserialize the packet
    deserialize_acc_create(&packet_acc_create, ctx->in_bytes);

    if(db_user_exists(userDB.db, packet_acc_create.username))
    {
        ctx->code = ERR_CLIENT_USER_EXISTS;
        goto error;
    }

    // Store credentials
    if(db_user_insert(userDB.db, packet_acc_create.username, packet_acc_create.password) != 0)
    {
        perror("db_user_add_id");
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }

    // Store user index
    user_id = db_user_add_id(index_userDB.db, packet_acc_create.username);
    if(user_id < 0)
    {
        perror("db_user_add_id");
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }
    ctx->user_id = user_id;

    // Create and serialize response
    packet_sys_success.header      = NULL;
    packet_sys_success.packet_type = ACC_Create;
    ctx->out_header.payload_len    = (uint16_t)serialize_sys_success(&ctx->out_bytes, &packet_sys_success, &ctx->err) - PACKET_CLIENT_HEADER_SIZE;

    dbm_close(userDB.db);
    dbm_close(index_userDB.db);
    return 0;

error:
    dbm_close(userDB.db);
    dbm_close(index_userDB.db);
    return -1;
}

ssize_t account_login(context_t *ctx)
{
    packet_acc_login_t         packet_acc_login;
    packet_acc_login_success_t packet_acc_login_success;

    DBO  userDB;
    DBO  index_userDB;
    char user_name[]  = "users";
    char index_name[] = "index_user";

    uint8_t *password;
    int      user_id;

    userDB.name       = user_name;
    userDB.db         = NULL;
    index_userDB.name = index_name;
    index_userDB.db   = NULL;

    printf("in account_login %d \n", ctx->client_fd);

    if(database_open(&userDB, &ctx->err) < 0)
    {
        perror("database error");
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }

    if(database_open(&index_userDB, &ctx->err) < 0)
    {
        perror("database error");
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }

    // Deserialize the packet
    deserialize_acc_login(&packet_acc_login, ctx->in_bytes);

    // Check if the user exists
    if(!db_user_exists(userDB.db, packet_acc_login.username))
    {    // ...if it does not...
        ctx->code = ERR_CLIENT_INVALID_AUTH_INFO;
        goto error;
    }

    // Fetch the password
    password = db_user_fetch_password(userDB.db, packet_acc_login.username);
    if(password == NULL)
    {
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }

    // Verify the password
    if(memcmp(password, packet_acc_login.password, strlen(packet_acc_login.password)) != 0)    // BUG: Lots of potentional for memory security issues here
    {
        free(password);
        ctx->code = ERR_CLIENT_INVALID_AUTH_INFO;
        goto error;
    }

    // Fetch the user's id
    user_id = db_user_fetch_id(index_userDB.db, packet_acc_login.username);

    if(user_id > UINT16_MAX)    // Check upper limit
    {
        // user_id is unexpectedly way too big...
        fprintf(stderr, "db_user_fetch_id: User ID is bigger than the UINT16_MAX.\n");
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }

    if(user_id < 0)    // Check lower limit
    {
        fprintf(stderr, "account login retrieve_int error\n");
        ctx->code = ERR_SERVER_FAULT;
        goto error;
    }

    // NOTE: user_id should be safe to cast to uint16_t now.

    // Create and serialize response
    packet_acc_login_success.header = NULL;
    packet_acc_login_success.id     = (uint16_t)user_id;
    ctx->out_header.payload_len     = (uint16_t)serialize_acc_login_success(&ctx->out_bytes, &packet_acc_login_success, &ctx->err) - PACKET_CLIENT_HEADER_SIZE;

    dbm_close(userDB.db);
    dbm_close(index_userDB.db);
    free(password);
    return 0;

error:
    dbm_close(userDB.db);
    dbm_close(index_userDB.db);
    return -1;
}

ssize_t account_logout(context_t *ctx)
{
    printf("in account_logout %d \n", ctx->client_fd);

    free(ctx->out_bytes);
    ctx->out_bytes = NULL;

    return -1;
}
