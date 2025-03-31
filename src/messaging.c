#include "messaging.h"
#include "account.h"
#include "chat.h"
#include "database.h"
#include "io.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TIMEOUT 3000    // 3s
// testing
#define MSG_COUNT 0x00000064
uint16_t user_count = 0;            // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)
uint32_t msg_count  = MSG_COUNT;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)
int      user_index = 0;            // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

static ssize_t execute_functions(request_t *request, const funcMapping functions[]);
static void    serialize_sm_diagnostic(char *msg);
static void    count_user(const int *sessions);
static void    send_user_count(int sm_fd, char *msg, int *err);

static const codeMapping code_map[] = {
    {OK,              ""                                  },
    {INVALID_USER_ID, "Invalid User ID"                   },
    {INVALID_AUTH,    "Invalid Authentication Information"},
    {USER_EXISTS,     "User Already exist"                },
    {SERVER_ERROR,    "Server Error"                      },
    {INVALID_REQUEST, "Invalid Request"                   },
    {REQUEST_TIMEOUT, "Request Timeout"                   }
};

const char *code_to_string(const code_t *code)
{
    for(size_t i = 0; i < sizeof(code_map) / sizeof(code_map[0]); i++)
    {
        if(code_map[i].code == *code)
        {
            return code_map[i].msg;
        }
    }
    return "UNKNOWN_STATUS";
}

static const struct fsm_transition transitions[] = {
    {START,            REQUEST_HANDLER,  request_handler },
    {REQUEST_HANDLER,  HEADER_HANDLER,   header_handler  },
    {HEADER_HANDLER,   BODY_HANDLER,     body_handler    },
    {BODY_HANDLER,     PROCESS_HANDLER,  process_handler },
    {PROCESS_HANDLER,  RESPONSE_HANDLER, response_handler},
    {RESPONSE_HANDLER, END,              NULL            },
    {REQUEST_HANDLER,  ERROR_HANDLER,    error_handler   },
    {HEADER_HANDLER,   ERROR_HANDLER,    error_handler   },
    {BODY_HANDLER,     ERROR_HANDLER,    error_handler   },
    {PROCESS_HANDLER,  ERROR_HANDLER,    error_handler   },
    {ERROR_HANDLER,    END,              NULL            },
};

static ssize_t execute_functions(request_t *request, const funcMapping functions[])
{
    for(size_t i = 0; functions[i].type != SYS_Success; i++)
    {
        if(request->type == functions[i].type)
        {
            return functions[i].func(request);
        }
    }
    printf("Not builtin command: %d\n", *(uint8_t *)request->content);
    return 1;
}

static void serialize_sm_diagnostic(char *msg)
{
    char    *ptr;
    uint16_t msg_payload_len = htons(MSG_PAYLOAD_LEN);

    ptr = msg;

    *ptr++ = SVR_Diagnostic;
    *ptr++ = VERSION;
    memcpy(ptr, &msg_payload_len, sizeof(msg_payload_len));
    ptr += sizeof(msg_payload_len);

    *ptr++ = INTEGER;
    *ptr++ = sizeof(user_count);
    ptr += sizeof(user_count);

    *ptr++ = INTEGER;
    *ptr++ = sizeof(msg_count);
}

static void count_user(const int *sessions)
{
    // printf("user_index: %d\n", user_index);
    user_count = 0;
    for(int i = 1; i < MAX_FDS; i++)
    {
        // printf("user id: %d\n", sessions[i]);
        if(sessions[i] != -1)
        {
            user_count++;
        }
    }
    printf("user_count: %d\n", user_count);
}

static void send_user_count(int sm_fd, char *msg, int *err)
{
    char      *ptr;
    int        fd;
    const char log[] = "./text.txt";

    ptr = msg;
    // move 6 bytes
    ptr += SM_HEADER_SIZE + 1 + 1;
    user_count = htons(user_count);
    memcpy(ptr, &user_count, sizeof(user_count));
    ptr += sizeof(user_count) + 1 + 1;

    msg_count = htonl(msg_count);
    memcpy(ptr, &msg_count, sizeof(msg_count));
    msg_count = ntohl(msg_count);

    printf("send_user_count\n");

    // testing
    fd = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if(fd == -1)
    {
        perror("open");
        errno = 0;
    }
    else
    {
        write_fully(fd, msg, MSG_LEN, err);
        close(fd);
    }
    // testing

    if(write_fully(sm_fd, msg, MSG_LEN, err) < 0)
    {
        perror("send_user_count failed");
        errno = 0;
    }
}

void error_response(request_t *request)
{
    char *ptr;

    // server default to 0
    uint16_t    sender_id = SERVER_ID;
    const char *msg;
    uint8_t     msg_len;

    ptr = (char *)request->response;
    // tag
    *ptr++ = SYS_Error;
    // version
    *ptr++ = VERSION;

    // sender_id
    sender_id = htons(sender_id);
    memcpy(ptr, &sender_id, sizeof(sender_id));
    ptr += sizeof(sender_id);

    msg     = code_to_string(&request->code);
    msg_len = (uint8_t)strlen(msg);

    request->response_len = (uint16_t)(request->response_len + (sizeof(uint8_t) + sizeof(uint8_t) + msg_len));

    // payload len
    request->response_len = htons(request->response_len);
    memcpy(ptr, &request->response_len, sizeof(request->response_len));
    ptr += sizeof(request->response_len);

    *ptr++ = INTEGER;
    *ptr++ = sizeof(uint8_t);

    memcpy(ptr, &request->code, sizeof(uint8_t));
    ptr += sizeof(uint8_t);

    *ptr++ = UTF8STRING;
    memcpy(ptr, &msg_len, sizeof(msg_len));
    ptr += sizeof(msg_len);

    memcpy(ptr, msg, msg_len);
}

void event_loop(int server_fd, int sm_fd, int *err)
{
    struct pollfd fds[MAX_FDS];
    // user_ids
    int     sessions[MAX_FDS];
    int     client_fd;
    int     added;
    char    db_name[] = "meta_user";
    DBO     meta_userDB;
    ssize_t result;
    char    msg[MSG_LEN];

    meta_userDB.name = db_name;

    if(init_pk(&meta_userDB, USER_PK) < 0)
    {
        perror("init_pk error\n");
        goto cleanup;
    }

    if(database_open(&meta_userDB, err) < 0)
    {
        perror("database error");
        goto cleanup;
    }

    serialize_sm_diagnostic(msg);

    fds[0].fd     = server_fd;
    fds[0].events = POLLIN;
    for(int i = 1; i < MAX_FDS; i++)
    {
        fds[i].fd   = -1;
        sessions[i] = -1;
    }

    while(running)
    {
        errno = 0;
        printf("polling...\n");
        result = poll(fds, MAX_FDS, TIMEOUT);
        // printf("result %d\n", (int)result);
        if(result == -1)
        {
            if(errno == EINTR)
            {
                goto cleanup;
            }
            perror("Poll error");
            goto cleanup;
        }
        if(result == 0)
        {
            printf("syncing meta_user...\n");

            // update user index
            if(store_int(meta_userDB.db, USER_PK, user_index) != 0)
            {
                perror("update user_index");
                goto cleanup;
            }
            count_user(sessions);
            send_user_count(sm_fd, msg, err);
            continue;
        }

        // Check for new connection
        if(fds[0].revents & POLLIN)
        {
            client_fd = accept(server_fd, NULL, 0);
            if(client_fd < 0)
            {
                if(errno == EINTR)
                {
                    goto cleanup;
                }
                perror("Accept failed");
                continue;
            }

            // Add new client to poll list
            added = 0;
            for(int i = 1; i < MAX_FDS; i++)
            {
                if(fds[i].fd == -1)
                {
                    fds[i].fd     = client_fd;
                    fds[i].events = POLLIN;
                    added         = 1;
                    break;
                }
            }
            if(!added)
            {
                char too_many[] = "Too many clients, rejecting connection\n";

                printf("%s", too_many);
                write_fully(client_fd, &too_many, (ssize_t)strlen(too_many), err);

                close(client_fd);
                continue;
            }
        }

        // Check existing clients for data
        for(int i = 1; i < MAX_FDS; i++)
        {
            if(fds[i].fd != -1)
            {
                if(fds[i].revents & POLLIN)
                {
                    request_t      request;
                    fsm_state_func perform;
                    fsm_state_t    from_id;
                    fsm_state_t    to_id;

                    from_id = START;
                    to_id   = REQUEST_HANDLER;

                    request.err    = 0;
                    request.client = &fds[i];
                    // user_id
                    request.session_id   = &sessions[i];
                    request.len          = HEADER_SIZE;
                    request.response_len = 3;
                    request.fds          = fds;
                    request.content      = malloc(HEADER_SIZE);
                    if(request.content == NULL)
                    {
                        perror("Malloc failed to allocate memory\n");
                        close(fds[i].fd);
                        fds[i].fd   = -1;
                        sessions[i] = -1;
                        continue;
                    }

                    memset(request.response, 0, RESPONSE_SIZE);

                    request.code = OK;

                    printf("event_loop session_id %d\n", *request.session_id);

                    do
                    {
                        perform = fsm_transition(from_id, to_id, transitions, sizeof(transitions));
                        if(perform == NULL)
                        {
                            printf("illegal state %d, %d \n", from_id, to_id);
                            free(request.content);
                            close(fds[i].fd);
                            fds[i].fd     = -1;
                            fds[i].events = 0;
                            sessions[i]   = -1;
                            break;
                        }
                        // printf("from_id %d\n", from_id);
                        from_id = to_id;
                        to_id   = perform(&request);
                    } while(to_id != END);
                }
                if(fds[i].revents & (POLLHUP | POLLERR))
                {
                    // Client disconnected or error, close and clean up
                    printf("oops...\n");
                    close(fds[i].fd);
                    fds[i].fd     = -1;
                    fds[i].events = 0;
                    sessions[i]   = -1;
                    continue;
                }
            }
        }
    }

    printf("syncing meta_user...\n");
    // update user index
    if(store_int(meta_userDB.db, USER_PK, user_index) != 0)
    {
        perror("update user_index");
    }
    dbm_close(meta_userDB.db);
    return;

cleanup:
    printf("syncing meta_user in cleanup...\n");
    store_int(meta_userDB.db, USER_PK, user_index);
    dbm_close(meta_userDB.db);
}

fsm_state_t request_handler(void *args)
{
    request_t *request;
    ssize_t    nread;

    request = (request_t *)args;
    printf("in request_handler %d\n", request->client->fd);

    // Read first 6 bytes from fd
    errno = 0;
    nread = read_fully(request->client->fd, (char *)request->content, request->len, &request->err);
    printf("request_handler nread %d\n", (int)nread);
    if(nread < 0)
    {
        perror("Read_fully error\n");
        return ERROR_HANDLER;
    }

    if(nread < (ssize_t)request->len)
    {
        request->code = INVALID_REQUEST;
        return ERROR_HANDLER;
    }
    return HEADER_HANDLER;
}

fsm_state_t header_handler(void *args)
{
    request_t *request;

    uint16_t sender_id;
    uint16_t len;
    char    *ptr;

    request = (request_t *)args;

    printf("in header_handler %d\n", request->client->fd);

    ptr = (char *)request->content;

    memcpy(&request->type, ptr, sizeof(request->type));
    ptr += sizeof(request->type) + sizeof(uint8_t);

    memcpy(&sender_id, ptr, sizeof(sender_id));
    request->sender_id = ntohs(sender_id);
    ptr += sizeof(sender_id);

    printf("sender_id: %u\n", request->sender_id);

    memcpy(&len, ptr, sizeof(len));
    // printf("len size (before ntohs): %u\n", len);
    request->len = ntohs(len);
    printf("len size (after ntohs): %u\n", (uint16_t)request->len);

    return BODY_HANDLER;
}

fsm_state_t body_handler(void *args)
{
    request_t *request;
    ssize_t    nread;
    void      *buf;

    request = (request_t *)args;
    printf("in header_handler %d\n", request->client->fd);

    printf("len size: %u\n", (uint16_t)(request->len + HEADER_SIZE));

    buf = realloc(request->content, request->len + HEADER_SIZE);
    if(!buf)
    {
        perror("Failed to realloc buf");
        return ERROR_HANDLER;
    }
    request->content = buf;

    nread = read_fully(request->client->fd, (char *)request->content + HEADER_SIZE, request->len, &request->err);
    if(nread < 0)
    {
        perror("Read_fully error\n");
        return ERROR_HANDLER;
    }

    return PROCESS_HANDLER;
}

fsm_state_t process_handler(void *args)
{
    request_t *request;
    ssize_t    result;

    request = (request_t *)args;

    printf("in process_handler %d\n", request->client->fd);

    result = execute_functions(request, acc_func);
    if(result <= 0)
    {
        return (result < 0) ? ERROR_HANDLER : RESPONSE_HANDLER;
    }

    result = execute_functions(request, chat_func);
    if(result <= 0)
    {
        return (result < 0) ? ERROR_HANDLER : RESPONSE_HANDLER;
    }

    request->code = INVALID_REQUEST;
    return ERROR_HANDLER;
}

fsm_state_t response_handler(void *args)
{
    request_t *request;

    request = (request_t *)args;

    printf("in response_handler %d\n", request->client->fd);

    if(request->type != CHT_Send)
    {
        request->response_len = (uint16_t)(HEADER_SIZE + ntohs(request->response_len));
        printf("response_len: %d\n", (request->response_len));

        write_fully(request->client->fd, request->response, request->response_len, &request->err);
    }

    free(request->content);

    // for linux
    // close(request->client->fd);
    // request->client->fd     = -1;
    // request->client->events = 0;
    // *request->session_id    = -1;
    return END;
}

fsm_state_t error_handler(void *args)
{
    request_t *request;

    request = (request_t *)args;
    printf("in error_handler %d: %d\n", request->client->fd, (int)request->code);

    if(request->type != ACC_Logout)
    {
        error_response(request);
        request->response_len = (uint16_t)(HEADER_SIZE + ntohs(request->response_len));
    }
    printf("response_len: %d\n", (request->response_len));

    write_fully(request->client->fd, request->response, request->response_len, &request->err);

    free(request->content);
    close(request->client->fd);
    request->client->fd     = -1;
    request->client->events = 0;
    *request->session_id    = -1;
    return END;
}
