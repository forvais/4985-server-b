// cppcheck-suppress-file unusedStructMember

#ifndef MESSAGING_H
#define MESSAGING_H

#include "fsm.h"
#include "state.h"
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

extern int user_count;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)
extern int user_index;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

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

typedef struct codeMapping
{
    code_t      code;
    const char *msg;
} codeMapping;

typedef struct funcMapping
{
    type_t type;
    ssize_t (*func)(context_t *ctx);
} funcMapping;

typedef enum
{
    USR_Count = 0x0A
} sm_type_t;

const char *code_to_string(const code_t *code);

void error_response(context_t *ctx);

void event_loop(app_state_t *state, int timeout, int *err);

fsm_state_t request_handler(void *args);
fsm_state_t header_handler(void *args);
fsm_state_t body_handler(void *args);
fsm_state_t process_handler(void *args);
fsm_state_t response_handler(void *args);
fsm_state_t error_handler(void *args);

#endif
