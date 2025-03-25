#include "messaging.h"
#include "account.h"
#include "chat.h"
#include "database.h"
#include "io.h"
#include "packets.h"
#include "serializers.h"
#include "state.h"
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

int user_count = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)
int user_index = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

static ssize_t execute_functions(context_t *ctx, const funcMapping functions[]);
static void    send_user_count(int fd, size_t count, int *err);

static int handle_server_incoming_connections(app_state_t *state, int fd);
static int handle_client_data_in(app_state_t *state, session_t *session);
static int handle_client_disconnect(app_state_t *state, session_t *session);

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

static ssize_t execute_functions(context_t *ctx, const funcMapping functions[])
{
    for(size_t i = 0; functions[i].type != SYS_Success; i++)
    {
        if(ctx->in_header.packet_type == functions[i].type)
        {
            return functions[i].func(ctx);
        }
    }
    fprintf(stderr, "Unknown packet type: %d\n", ctx->in_header.packet_type);
    return 1;
}

static void send_user_count(int fd, size_t count, int *err)
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
    if(write_fully(fd, (char *)buf, (ssize_t)buf_size, err) < 0)
    {
        perror("send_user_count failed");
        errno = 0;
    }

    free(buf);
}

static int handle_server_incoming_connections(app_state_t *state, int sockfd)
{
    int connfd;

    // Accept new connections
    errno  = 0;
    connfd = accept(sockfd, NULL, 0);
    if(connfd < 0)
    {
        if(errno != EINTR)
        {
            perror("Accept failed");
        }

        return -1;
    }

    // Add new client to poll list
    app_state_register_client(state, connfd);

    return 0;
}

static int handle_client_data_in(app_state_t *state, session_t *session)
{
    context_t ctx;

    fsm_state_func perform;
    fsm_state_t    from_id;
    fsm_state_t    to_id;

    // Create pipeline context
    ctx_init(&ctx, state, session);
    printf("event_loop session_id %d\n", session->id);

    // Set FSM parameters
    from_id = START;
    to_id   = REQUEST_HANDLER;

    // Execute FSM pipeline
    do
    {
        perform = fsm_transition(from_id, to_id, transitions, sizeof(transitions));
        if(perform == NULL)
        {
            printf("illegal state %d, %d \n", from_id, to_id);
            app_state_remove_client_by_session(state, session);
            return -1;
        }

        from_id = to_id;
        to_id   = perform(&ctx);
    } while(to_id != END);

    ctx_destroy(&ctx);

    return 0;
}

static int handle_client_disconnect(app_state_t *state, session_t *session)
{
    // Client disconnected or error, close and clean up
    printf("oops...\n");
    app_state_remove_client_by_session(state, session);

    return 0;
}

void event_loop(app_state_t *state, int timeout, int *err)
{
    char db_name[] = "meta_user";
    DBO  meta_userDB;

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

    while(running)
    {
        const struct pollfd *server_pollfd = &state->pollfds[0];
        ssize_t              poll_result;

        errno = 0;

        // Setup polling
        poll_result = poll(state->pollfds, state->max_clients, timeout);
        if(poll_result == -1)
        {
            if(errno == EINTR)
            {
                goto cleanup;
            }
            perror("Poll error");
            goto cleanup;
        }
        if(poll_result == 0)    // On POLL timeout...
        {
            printf("syncing meta_user...\n");

            // update user index
            if(store_int(meta_userDB.db, USER_PK, user_index) != 0)
            {
                perror("update user_index");
                goto cleanup;
            }

            // Send user count to server manager
            send_user_count(state->smfd, state->connected_clients, err);
            continue;
        }

        // Handle new connections
        if(server_pollfd->revents & POLLIN)
        {
            handle_server_incoming_connections(state, server_pollfd->fd);
        }

        // Check existing clients for data
        for(size_t i = 1; i < state->max_clients; i++)
        {
            session_t           *client_session = &state->sessions[i];
            const struct pollfd *client_pollfd  = client_session->pollfd;

            if(client_session->id == -1)
            {
                continue;
            }

            if(client_pollfd->revents & POLLIN)    // If a [valid] client has incoming data...
            {
                handle_client_data_in(state, client_session);
            }

            if(client_pollfd->revents & (POLLHUP | POLLERR))    //  If they have disconnected gracefully or from a fatal error...
            {
                handle_client_disconnect(state, client_session);
            }
        }
    }

    // update user index
    printf("syncing meta_user...\n");
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
    context_t *ctx;
    ssize_t    nread;

    ctx = (context_t *)args;

    printf("in request_handler %d\n", ctx->client_fd);

    // Allocate enough bytes for a packet_client_header
    errno         = 0;
    ctx->in_bytes = (uint8_t *)calloc(PACKET_CLIENT_HEADER_SIZE, sizeof(uint8_t));
    if(ctx->in_bytes == NULL)
    {
        ctx->err  = errno;
        ctx->code = ERR_SERVER_FAULT;
        return ERROR_HANDLER;
    }

    // Read [PACKET_CLIENT_HEADER_SIZE] bytes into ctx->in_bytes from the client buffer
    errno = 0;
    nread = read_fully(ctx->client_fd, (char *)ctx->in_bytes, PACKET_CLIENT_HEADER_SIZE, &ctx->err);
    printf("request_handler nread %d\n", (int)nread);
    if(nread < 0)
    {
        perror("Read_fully error\n");
        return ERROR_HANDLER;
    }

    // If the amount read of bytes read is larger or smaller than the header size, the packet is invalid or corrupt
    if(nread != PACKET_CLIENT_HEADER_SIZE)
    {
        ctx->code = ERR_PACKET_INVALID;
        return ERROR_HANDLER;
    }

    return HEADER_HANDLER;
}

fsm_state_t header_handler(void *args)
{
    context_t *ctx = (context_t *)args;

    size_t header_size;

    printf("in header_handler %d\n", ctx->client_fd);

    // Deserialize ctx->in_bytes and parse the bytes by copying them into a packet_client_header_t struct
    header_size = deserialize_client_header(&ctx->in_header, ctx->in_bytes);
    if(header_size != PACKET_CLIENT_HEADER_SIZE)
    {    // If the [deserialized] header size is smaller or larger than expected, something went wrong
        ctx->code = ERR_SERVER_FAULT;
        return ERROR_HANDLER;
    }

    printf("\nIncoming header:\n");
    print_client_header(&ctx->in_header);
    printf("\n");

    return BODY_HANDLER;
}

fsm_state_t body_handler(void *args)
{
    context_t *ctx = (context_t *)args;

    uint8_t *buf;
    ssize_t  nread;

    printf("in body_handler %d\n", ctx->client_fd);

    // Expand the request->in_bytes buffer to fit the the rest of the body
    errno = 0;
    buf   = (uint8_t *)realloc(ctx->in_bytes, PACKET_CLIENT_HEADER_SIZE + ctx->in_header.payload_len);
    if(buf == NULL)
    {
        ctx->err  = errno;
        ctx->code = ERR_SERVER_FAULT;
        return ERROR_HANDLER;
    }
    ctx->in_bytes = buf;

    // Read [packet_client_header_t->bytes] into ctx->bytes (offset by/after the header bytes)
    ctx->err = 0;
    nread    = read_fully(ctx->client_fd, (char *)ctx->in_bytes + PACKET_CLIENT_HEADER_SIZE, ctx->in_header.payload_len, &ctx->err);
    if(nread < 0)
    {
        return ERROR_HANDLER;
    }

    return PROCESS_HANDLER;
}

fsm_state_t process_handler(void *args)
{
    context_t *ctx;
    ssize_t    result;

    ctx = (context_t *)args;

    printf("in process_handler %d\n", ctx->client_fd);

    result = execute_functions(ctx, acc_func);
    if(result <= 0)
    {
        return (result < 0) ? ERROR_HANDLER : RESPONSE_HANDLER;
    }

    result = execute_functions(ctx, chat_func);
    if(result <= 0)
    {
        return (result < 0) ? ERROR_HANDLER : RESPONSE_HANDLER;
    }

    ctx->code = ERR_PACKET_INVALID;
    return ERROR_HANDLER;
}

fsm_state_t response_handler(void *args)
{
    context_t *ctx;

    ctx = (context_t *)args;

    printf("in response_handler %d\n", ctx->client_fd);

    // Exit early if there is no response to send
    if(ctx->out_bytes == NULL)
    {
        return END;
    }

    // Write response to client
    if(write_fully(ctx->client_fd, ctx->out_bytes, PACKET_CLIENT_HEADER_SIZE + ctx->out_header.payload_len, &ctx->err) < 0)
    {
        printf("Wrote to closed fd.\n");
    }

    return END;
}

fsm_state_t error_handler(void *args)
{
    context_t *ctx;

    packet_sys_error_t packet_error;

    ctx = (context_t *)args;
    printf("in error_handler %d: %d\n", ctx->client_fd, (int)ctx->code);

    if(ctx->in_header.packet_type != ACC_Logout)    // NOTE: Unsure when ACC_LOGOUT would ever have a chance to err.
    {
        // Define packet_sys_error parameters
        packet_error.header = NULL;
        packet_error.code   = (uint8_t)ctx->code;
        strhcpy(&packet_error.message, packet_error_str(packet_error.code));    // packet_error_str returns const char *, which packet_error.msg doesn't like... Use strhcpy to copy to heap.

        // Serialize the packet
        ctx->out_header.payload_len = (uint16_t)serialize_sys_error(&ctx->out_bytes, &packet_error, &ctx->err) - PACKET_CLIENT_HEADER_SIZE;
    }
    printf("response_len: %d\n", (PACKET_CLIENT_HEADER_SIZE + ctx->out_header.payload_len));

    // Send err packet to client.
    write_fully(ctx->client_fd, ctx->out_bytes, PACKET_CLIENT_HEADER_SIZE + ctx->out_header.payload_len, &ctx->err);

    return END;
}
