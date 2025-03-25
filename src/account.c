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

ssize_t account_create(request_t *request)
{
    packet_acc_create_t  packet_acc_create;
    packet_sys_success_t packet_sys_success;

    DBO  userDB;
    DBO  index_userDB;
    char user_name[]  = "users";
    char index_name[] = "index_user";

    int user_id;

    uint8_t *response_buf;

    userDB.name       = user_name;
    userDB.db         = NULL;
    index_userDB.name = index_name;
    index_userDB.db   = NULL;

    printf("in account_create %d \n", request->client->fd);

    if(database_open(&userDB, &request->err) < 0)
    {
        perror("database error");
        request->code = SERVER_ERROR;
        goto error;
    }

    if(database_open(&index_userDB, &request->err) < 0)
    {
        perror("database error");
        request->code = SERVER_ERROR;
        goto error;
    }

    // Deserialize the packet
    deserialize_acc_create(&packet_acc_create, request->content);

    // Check for an existing user
    if(db_user_exists(userDB.db, packet_acc_create.username))
    {
        perror("db_user_exists");
        request->code = USER_EXISTS;
        goto error;
    }

    // Store credentials
    if(db_user_insert(userDB.db, packet_acc_create.username, packet_acc_create.password) != 0)
    {
        perror("db_user_insert");
        request->code = SERVER_ERRER;
        goto error;
    }

    // Store user index
    user_id = db_user_add_id(index_userDB.db, packet_acc_create.username);
    if(user_id < 0)
    {
        perror("db_user_add_id");
        request->code = SERVER_ERROR;
        goto error;
    }
    *request->session_id = user_id;

    // Create and serialize response
    packet_sys_success.header      = NULL;
    packet_sys_success.packet_type = ACC_Create;
    request->response_len          = (uint16_t)serialize_sys_success(&response_buf, &packet_sys_success, &request->err);

    // ... Copy response buf to request->response -- required to copy data from dynamic buffer to a static buffer
    errno = 0;
    if(memcpyds(request->response, response_buf, sizeof(request->response), request->response_len) == 0)
    {
        perror("memcpyds");
        request->code = SERVER_ERROR;
        goto error;
    }

    dbm_close(userDB.db);
    dbm_close(index_userDB.db);
    return 0;

error:
    dbm_close(userDB.db);
    dbm_close(index_userDB.db);
    return -1;
}

ssize_t account_login(request_t *request)
{
    packet_acc_login_t         packet_acc_login;
    packet_acc_login_success_t packet_acc_login_success;

    DBO  userDB;
    DBO  index_userDB;
    char user_name[]  = "users";
    char index_name[] = "index_user";

    uint8_t *password;
    int      user_id;

    uint8_t *response_buf;

    userDB.name       = user_name;
    userDB.db         = NULL;
    index_userDB.name = index_name;
    index_userDB.db   = NULL;

    printf("in account_login %d \n", request->client->fd);

    if(database_open(&userDB, &request->err) < 0)
    {
        perror("database error");
        request->code = SERVER_ERROR;
        goto error;
    }

    if(database_open(&index_userDB, &request->err) < 0)
    {
        perror("database error");
        request->code = SERVER_ERROR;
        goto error;
    }

    // Deserialize the packet
    deserialize_acc_login(&packet_acc_login, request->content);

    // Check if the user exists
    if(!db_user_exists(userDB.db, packet_acc_login.username))
    {    // ...if it does not...
        request->code = INVALID_AUTH;
        goto error;
    }

    // Fetch the password
    password = db_user_fetch_password(userDB.db, packet_acc_login.username);
    if(password == NULL)
    {
        request->code = SERVER_ERROR;
        goto error;
    }

    // Verify the password
    if(memcmp(password, packet_acc_login.password, strlen(packet_acc_login.password)) != 0)    // BUG: Lots of potentional for memory security issues here
    {
        free(password);
        request->code = INVALID_AUTH;
        goto error;
    }

    // Fetch the user's id
    user_id = db_user_fetch_id(index_userDB.db, packet_acc_login.username);

    if(user_id > UINT16_MAX)    // Check upper limit
    {
        // user_id is unexpectedly way too big...
        fprintf(stderr, "db_user_fetch_id: User ID is bigger than the UINT16_MAX.\n");
        request->code = SERVER_ERROR;
        goto error;
    }

    if(user_id < 0)    // Check lower limit
    {
        fprintf(stderr, "account login retrieve_int error\n");
        request->code = SERVER_ERROR;
        goto error;
    }

    // NOTE: user_id should be safe to cast to uint16_t now.

    // Create and serialize response
    packet_acc_login_success.header = NULL;
    packet_acc_login_success.id     = (uint16_t)user_id;
    request->response_len           = (uint16_t)serialize_acc_login_success(&response_buf, &packet_acc_login_success, &request->err);

    // ... Copy response buf to request->response -- required to copy data from dynamic buffer to a static buffer
    errno = 0;
    if(memcpyds(request->response, response_buf, sizeof(request->response), request->response_len) == 0)
    {
        perror("memcpyds");
        request->code = SERVER_ERROR;
        goto error;
    }

    dbm_close(userDB.db);
    dbm_close(index_userDB.db);
    free(password);
    return 0;

error:
    dbm_close(userDB.db);
    dbm_close(index_userDB.db);
    return -1;
}

ssize_t account_logout(request_t *request)
{
    printf("in account_logout %d \n", request->client->fd);

    request->response_len = 0;
    request->err          = 0;

    return -1;
}
