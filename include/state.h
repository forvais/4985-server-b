#ifndef CONTEXT_H
#define CONTEXT_H

#include "packets.h"
#include <stdint.h>

typedef struct
{
    int            id;
    int            user_id;
    struct pollfd *pollfd;
} session_t;

typedef struct
{
    size_t max_clients;
    size_t connected_clients;

    int sockfd;
    int smfd;

    struct pollfd *pollfds;     // All connected clients.
    session_t     *sessions;    // List of client ids
} app_state_t;

/* The "Context" contains shared data between different modules of the request-response pipeline */
typedef struct
{
    // State
    session_t   *session;
    app_state_t *state;
    int          client_fd;    // Short-hand for session->pollfd->fd
    int          user_id;      // Short-hand for session->user_id

    // Error State
    int       err;     // Saved errno value.
    SRV_ERR_T code;    // An API error.

    // Incoming Data
    packet_client_header_t in_header;
    uint8_t               *in_bytes;    // Contains bytes for both the header and the payload.

    // Outgoing Data
    packet_client_header_t out_header;    // Only really used for the sender_id property and possibly the "out_header->payload_len" property (but maybe not?).
    uint8_t               *out_bytes;     // Contains bytes for both the header and the payload.
} context_t;

int        app_state_init(app_state_t *state, size_t max_clients);
void       app_state_destroy(app_state_t *state);
session_t *app_state_register_client(app_state_t *state, int fd);
void       app_state_remove_client_by_session(app_state_t *state, session_t *session);

int  ctx_init(context_t *ctx, app_state_t *state, session_t *session);
void ctx_destroy(context_t *ctx);

#endif
