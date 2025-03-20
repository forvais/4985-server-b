#include "packets.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct
{
    PACKET_TYPE type;
    const char *name;
} packet_type_t;

typedef struct
{
    ERR         code;
    const char *msg;
} packet_error_t;

static const packet_type_t packet_type_map[] = {
    {PACKET_SYS_SUCCESS,       "Success"      },
    {PACKET_SYS_ERROR,         "Error"        },
    {PACKET_ACC_LOGIN,         "Login"        },
    {PACKET_ACC_LOGIN_SUCCESS, "Login Success"},
    {PACKET_ACC_LOGOUT,        "Logout"       },
    {PACKET_ACC_CREATE,        "Create"       },
    {PACKET_ACC_EDIT,          "Edit"         },
    {PACKET_CHT_SEND,          "Chat Send"    },
};

static const packet_error_t packet_error_map[] = {
    {ERR_CLIENT_INVALID_USER_ID,   "Invalid User Id"                   },
    {ERR_CLIENT_INVALID_AUTH_INFO, "Invalid Authentication Information"},
    {ERR_CLIENT_USER_EXISTS,       "User Already Exists"               },
    {ERR_SERVER_FAULT,             "Generic Server Failure"            },
    {ERR_PACKET_INVALID,           "Invalid Request"                   },
    {ERR_PACKET_REQUEST_TIMEOUT,   "Request Timeout"                   },
};

const char *packet_type_str(uint8_t type)
{
    for(size_t i = 0; i < sizeof(packet_type_map) / sizeof(packet_type_map[0]); i++)
    {
        if(packet_type_map[i].type == type)
        {
            return packet_type_map[i].name;
        }
    }

    return NULL;
}

const char *packet_error_str(uint8_t code)
{
    for(size_t i = 0; i < sizeof(packet_error_map) / sizeof(packet_error_map[0]); i++)
    {
        if(packet_error_map[i].code == code)
        {
            return packet_error_map[i].msg;
        }
    }

    return NULL;
}

void print_header(const packet_header_t *header)
{
    if(header)
    {
        const char *name = packet_type_str(header->packet_type);

        printf("Header Packet Type: %d (%s)\n", header->packet_type, name ? name : "Unknown");
        printf("Header Version: %d\n", header->version);
        printf("Header Sender Id: %d\n", header->sender_id);
        printf("Header Payload Length: %d\n", header->payload_len);
    }
}

void print_sys_success(const packet_sys_success_t *packet)
{
    if(packet)
    {
        print_header(packet->header);
        printf("Packet Type: %d\n", packet->packet_type);
    }
}

void print_sys_error(const packet_sys_error_t *packet)
{
    if(packet)
    {
        print_header(packet->header);
        printf("Code: %d\n", packet->code);
        printf("Message: %s\n", packet->message);
    }
}

void print_acc_login_success(const packet_acc_login_success_t *packet)
{
    if(packet)
    {
        print_header(packet->header);
        printf("Id: %d\n", packet->id);
    }
}

void print_acc_login(const packet_acc_login_t *packet)
{
    if(packet)
    {
        print_header(packet->header);
        printf("Username: %s\n", packet->username);
        printf("Password: %s\n", packet->password);
    }
}

void print_acc_logout(const packet_acc_logout_t *packet)
{
    if(packet)
    {
        print_header(packet->header);
    }
}

void print_acc_create(const packet_acc_create_t *packet)
{
    if(packet)
    {
        print_header(packet->header);
        printf("Username: %s\n", packet->username);
        printf("Password: %s\n", packet->password);
    }
}

void print_acc_edit(const packet_acc_edit_t *packet)
{
    if(packet)
    {
        print_header(packet->header);
        printf("Field: %d\n", packet->edit_field);
        printf("Value: %s\n", packet->edit_value);
    }
}

void print_cht_send(const packet_cht_send_t *packet)
{
    if(packet)
    {
        print_header(packet->header);
        printf("Timestamp: %s\n", packet->generalized_time);
        printf("Content: %s\n", packet->content);
        printf("Username: %s\n", packet->username);
    }
}

void clean_sys_success(packet_sys_success_t *packet)
{
    free(packet->header);
}

void clean_sys_error(packet_sys_error_t *packet)
{
    free(packet->header);
    free(packet->message);
}

void clean_acc_login_success(packet_acc_login_success_t *packet)
{
    free(packet->header);
}

void clean_acc_create(packet_acc_create_t *packet)
{
    free(packet->header);
    free(packet->username);
    free(packet->password);
}

void clean_acc_login(packet_acc_login_t *packet)
{
    free(packet->header);
    free(packet->username);
    free(packet->password);
}

void clean_acc_logout(packet_acc_logout_t *packet)
{
    free(packet->header);
}

void clean_acc_edit(packet_acc_edit_t *packet)
{
    free(packet->header);
    free(packet->edit_value);
}

void clean_cht_send(packet_cht_send_t *packet)
{
    free(packet->header);
    free(packet->generalized_time);
    free(packet->content);
    free(packet->username);
}
