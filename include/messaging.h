// cppcheck-suppress-file unusedStructMember

#ifndef MESSAGING_H
#define MESSAGING_H

#include "fsm.h"
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define HEADER_SIZE 6
#define RESPONSE_SIZE 256
#define SERVER_ID 0x0000
#define MAX_CLIENTS 2
#define MAX_FDS (MAX_CLIENTS + 1)
#define VERSION 0x03
#define SM_HEADER_SIZE 4
#define MSG_LEN 14
#define MSG_PAYLOAD_LEN 0x000A

extern uint16_t user_count;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)
extern uint32_t msg_count;     // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)
extern int      user_index;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

typedef enum
{
    BOOLEAN         = 0x01,
    INTEGER         = 0x02,
    null            = 0x05,
    ENUMERATED      = 0x0A,
    UTF8STRING      = 0x0C,
    SEQUENCE        = 0x10,
    SEQUENCEOF      = 0x30,
    PrintableString = 0x13,
    UTCTime         = 0x17,
    GeneralizedTime = 0x18,
} tag_t;

typedef enum
{
    // 0
    OK = 0x00,
    // 11
    INVALID_USER_ID = 0x0B,
    // 12
    INVALID_AUTH = 0x0C,
    // 13
    USER_EXISTS = 0x0D,
    // 21
    SERVER_ERROR = 0x15,
    // 31
    INVALID_REQUEST = 0x1F,
    // 32
    REQUEST_TIMEOUT = 0x20,
} code_t;

typedef enum
{
    // 0
    SYS_Success = 0x00,
    // 1
    SYS_Error = 0x01,
    // 10
    ACC_Login = 0x0A,
    // 11
    ACC_Login_Success = 0x0B,
    // 12
    ACC_Logout = 0x0C,
    // 13
    ACC_Create = 0x0D,
    // 14
    ACC_Edit = 0x0E,
    // 20
    CHT_Send = 0x14,
    // 21
    CHT_Received = 0x15,
    // 30
    LST_Get = 0x1E,
    // 31
    LST_Response = 0x1F
} type_t;

typedef struct request_t
{
    void          *content;
    size_t         len;
    int            err;
    struct pollfd *client;
    int           *session_id;
    uint16_t       sender_id;
    uint8_t        type;
    code_t         code;
    uint8_t        response[RESPONSE_SIZE];
    uint16_t       response_len;
    struct pollfd *fds;
} request_t;

typedef struct codeMapping
{
    code_t      code;
    const char *msg;
} codeMapping;

typedef struct funcMapping
{
    type_t type;
    ssize_t (*func)(request_t *request);
} funcMapping;

typedef enum
{
    MAN_Error      = 0x01,
    SVR_Diagnostic = 0x0A,
    USR_Online     = 0x0B,
    SVR_Online     = 0x0C,
    SVR_Offline    = 0x0D,
    SVR_Start      = 0x14,
    SVR_Stop       = 0x15,
} sm_type_t;

const char *code_to_string(const code_t *code);

void error_response(request_t *request);

void event_loop(int server_fd, int sm_fd, int *err);

fsm_state_t request_handler(void *args);

fsm_state_t header_handler(void *args);

fsm_state_t body_handler(void *args);

fsm_state_t process_handler(void *args);

fsm_state_t response_handler(void *args);

fsm_state_t error_handler(void *args);

#endif
