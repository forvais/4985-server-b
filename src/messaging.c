#include "messaging.h"
#include "account.h"
#include "chat.h"
#include "database.h"
#include "io.h"
#include "packets.h"
#include "serializers.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TIMEOUT 3000    // 3s

int user_count = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)
int user_index = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

static ssize_t execute_functions(request_t *request, const funcMapping functions[]);
static void    count_user(const int *sessions);
static void    send_user_count(int sm_fd, int count, int *err);

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

static void count_user(const int *sessions)
{
    // printf("user_index: %d\n", user_index);
    user_count = 0;
    for(int i = 1; i < MAX_FDS; i++)
    {
        printf("user id: %d\n", sessions[i]);
        if(sessions[i] != -1)
        {
            user_count++;
        }
    }
    printf("user_count: %d\n", user_count);
}

static void send_user_count(int sm_fd, int count, int *err)
{
    packet_svr_diagnostic_t packet_svr_diagnostic;

    uint8_t *buf;
    size_t   buf_size;

    // Define packet svr_diagnostic parameters
    packet_svr_diagnostic.header            = NULL;
    packet_svr_diagnostic.message_count     = 0;
    packet_svr_diagnostic.user_online_count = (uint16_t)count;    // WARNING: UNSAFE CAST -- user_count could be way bigger than a uint16_t (65536) could handle...
                                                                  // Unlikely but should be aware.

    // Serialize the packet
    buf_size = serialize_svr_diagnostic(&buf, &packet_svr_diagnostic, err);

    // Write to buffer to the server manager
    printf("send_user_count\n");
    if(write_fully(sm_fd, (char *)buf, (ssize_t)buf_size, err) < 0)
    {
        perror("send_user_count failed");
        errno = 0;
    }
}

void error_response(request_t *request)
{
    packet_sys_error_t packet_error;

    uint8_t *buf;
    size_t   buf_size;

    // Define packet_sys_error parameters
    packet_error.header = NULL;
    packet_error.code   = (uint8_t)request->code;
    strhcpy(&packet_error.message, packet_error_str(packet_error.code));    // packet_error_str returns const char *, which packet_error.msg doesn't like... Use strhcpy to copy to heap.

    // Serialize the packet
    buf_size = serialize_sys_error(&buf, &packet_error, &request->err);

    // Copy to request.response
    memcpyds(&request->response, buf, sizeof(request->response), buf_size);    // Use memcpyds to copy dynamically allocated memory into static memory
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
            send_user_count(sm_fd, user_count, err);
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
                    request.len          = PACKET_CLIENT_HEADER_SIZE;
                    request.response_len = 3;
                    request.fds          = fds;
                    request.content      = malloc(PACKET_CLIENT_HEADER_SIZE);
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
    request_t *request = (request_t *)args;

    packet_client_header_t header;
    size_t                 header_size;

    // Deserialize the packet header
    header_size = deserialize_client_header(&header, request->content);
    if(header_size != PACKET_CLIENT_HEADER_SIZE)
    {
        return ERROR_HANDLER;
    }

    // Adapt to existing data model
    request->type      = header.packet_type;
    request->sender_id = header.sender_id;
    request->len       = header.payload_len;

    return BODY_HANDLER;
}

fsm_state_t body_handler(void *args)
{
    request_t *request = (request_t *)args;

    uint8_t *buf;
    ssize_t  nread;

    // Expand the request->content buffer to fit the the rest of the body
    buf = (uint8_t *)realloc(request->content, request->len + PACKET_CLIENT_HEADER_SIZE);
    if(buf == NULL)
    {
        return ERROR_HANDLER;
    }
    request->content = buf;

    // Read the rest of the packet
    request->err = 0;
    nread        = read_fully(request->client->fd, (char *)request->content + PACKET_CLIENT_HEADER_SIZE, request->len, &request->err);
    if(nread < 0)
    {
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

    write_fully(request->client->fd, request->response, request->response_len, &request->err);

    free(request->content);
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
        request->response_len = (uint16_t)(PACKET_CLIENT_HEADER_SIZE + ntohs(request->response_len));
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
