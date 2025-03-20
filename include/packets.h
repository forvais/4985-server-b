// cppcheck-suppress-file unusedStructMember

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <unistd.h>

#define PACKET_CLIENT_HEADER_SIZE 6
#define PACKET_SM_HEADER_SIZE 4
#define SENDER_ID_DEFAULT 0

typedef enum
{
    ERR_CLIENT_INVALID_USER_ID = 11,
    ERR_CLIENT_INVALID_AUTH_INFO,
    ERR_CLIENT_USER_EXISTS,
    ERR_SERVER_FAULT   = 21,
    ERR_PACKET_INVALID = 31,
    ERR_PACKET_REQUEST_TIMEOUT,
} ERR;

typedef enum
{
    PACKET_SYS_SUCCESS = 0,
    PACKET_SYS_ERROR,
    PACKET_ACC_LOGIN = 10,
    PACKET_ACC_LOGIN_SUCCESS,
    PACKET_ACC_LOGOUT,
    PACKET_ACC_CREATE,
    PACKET_ACC_EDIT,
    PACKET_CHT_SEND = 20,
    PACKET_LIST_GET = 30,
    PACKET_LIST_RESPONSE,
} SRV_PACKET_TYPE;

typedef enum
{
    PACKET_MAN_SUCCESS = 0,
    PACKET_MAN_ERROR,
    PACKET_SVR_DIAGNOSTIC = 10,
    PACKET_USR_ONLINE,
    PACKET_SVR_ONLINE,
    PACKET_SVR_OFFLINE,
    PACKET_SVR_START = 20,
    PACKET_SVR_STOP,
} SM_PACKET_TYPE;

typedef enum
{
    FILTER_NONE = 0,
    FILTER_ONLINE,
} PACKET_LIST_FILTERS;

typedef enum
{
    FIELD_USERNAME = 0,
    FIELD_PASSWORD,
} PACKET_ACC_FIELDS;

typedef struct
{
    uint8_t  packet_type;
    uint8_t  version;
    uint16_t sender_id;
    uint16_t payload_len;
} packet_client_header_t;

typedef struct
{
    uint8_t  packet_type;
    uint8_t  version;
    uint16_t payload_len;
} packet_sm_header_t;

typedef struct
{
    packet_client_header_t *header;
    void                   *body;
} packet_t;

typedef struct
{
    packet_client_header_t *header;
    uint8_t                 packet_type;
} packet_sys_success_t;

typedef struct
{
    packet_client_header_t *header;
    uint8_t                 code;
    char                   *message;
} packet_sys_error_t;

typedef struct
{
    packet_client_header_t *header;
    char                   *username;
    char                   *password;
} packet_acc_login_t;

typedef struct
{
    packet_client_header_t *header;
    uint16_t                id;
} packet_acc_login_success_t;

typedef struct
{
    packet_client_header_t *header;
} packet_acc_logout_t;

typedef struct
{
    packet_client_header_t *header;
    char                   *username;
    char                   *password;
} packet_acc_create_t;

typedef struct
{
    packet_client_header_t *header;
    uint8_t                 edit_field;
    char                   *edit_value;
} packet_acc_edit_t;

typedef struct
{
    packet_client_header_t *header;
    char                   *generalized_time;
    char                   *content;
    char                   *username;
} packet_cht_send_t;

typedef struct
{
    packet_client_header_t *header;
    uint8_t                 group_id;
    uint8_t                 filter;
} packet_lst_get_t;

const char *packet_type_str(uint8_t type);
const char *packet_error_str(uint8_t code);

void print_client_header(const packet_client_header_t *header);
void print_sm_header(const packet_sm_header_t *header);
void print_sys_success(const packet_sys_success_t *packet);
void print_sys_error(const packet_sys_error_t *packet);
void print_acc_login_success(const packet_acc_login_success_t *packet);
void print_acc_login(const packet_acc_login_t *packet);
void print_acc_logout(const packet_acc_logout_t *packet);
void print_acc_create(const packet_acc_create_t *packet);
void print_acc_edit(const packet_acc_edit_t *packet);
void print_cht_send(const packet_cht_send_t *packet);

void clean_sys_success(packet_sys_success_t *packet);
void clean_sys_error(packet_sys_error_t *packet);
void clean_acc_login_success(packet_acc_login_success_t *packet);
void clean_acc_create(packet_acc_create_t *packet);
void clean_acc_login(packet_acc_login_t *packet);
void clean_acc_logout(packet_acc_logout_t *packet);
void clean_acc_edit(packet_acc_edit_t *packet);
void clean_cht_send(packet_cht_send_t *packet);

#endif
