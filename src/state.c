#include "state.h"
#include <memory.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/poll.h>

#define FREE_IF_NOT_NULL(x)                                                                                                                                                                                                                                        \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if((x) != NULL)                                                                                                                                                                                                                                            \
        {                                                                                                                                                                                                                                                          \
            free((x));                                                                                                                                                                                                                                             \
        }                                                                                                                                                                                                                                                          \
    } while(0)

int app_state_init(app_state_t *state, size_t max_clients)
{
    memset(state, 0, sizeof(app_state_t));
    state->max_clients = max_clients;
    state->sockfd      = -1;
    state->smfd        = -1;

    // Allocate space for FDs
    state->pollfds = (struct pollfd *)calloc(max_clients, sizeof(struct pollfd));
    if(state->pollfds == NULL)
    {
        return -1;
    }
    memset(state->pollfds, -1, max_clients * sizeof(struct pollfd));

    // Allocate space for sessions
    state->sessions = (session_t *)calloc(max_clients, sizeof(session_t));
    if(state->sessions == NULL)
    {
        return -2;
    }
    memset(state->sessions, -1, max_clients * sizeof(session_t));

    return 0;
}

void app_state_destroy(app_state_t *state)
{
    memset(state->pollfds, 0, state->max_clients * sizeof(struct pollfd));
    memset(state->sessions, 0, state->max_clients * sizeof(session_t));

    free(state->pollfds);
    free(state->sessions);
}

session_t *app_state_register_client(app_state_t *state, int fd)
{
    session_t *session;
    bool       registered;

    // By default, no client has been registered
    registered = false;

    // Add FD to poll list and set session data
    for(size_t idx = 0; idx < state->max_clients; idx++)
    {
        struct pollfd *pollfd = &state->pollfds[idx];
        session               = &state->sessions[idx];

        if(pollfd->fd == -1 && session->id == -1)
        {
            pollfd->fd     = fd;
            pollfd->events = POLLIN;

            session->pollfd = pollfd;
            session->id     = (int)idx;    // TODO: Do actual limit checks

            state->connected_clients++;    // A client has successfully connected.
            registered = true;
            break;
        }
    }

    if(!registered)
    {
        session = NULL;
    }

    // BUG: Potential bug? Not sure what branch has an uninitialized session variable
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconditional-uninitialized"
    return session;
#pragma GCC diagnostic pop
}

void app_state_remove_client_by_session(app_state_t *state, session_t *session)
{
    const size_t idx = (size_t)session->id;    // NOTE: session->id can not be anything but a size_t at this point

    close(session->pollfd->fd);

    state->connected_clients--;    // A client has disconnected.
    memset(&state->pollfds[idx], -1, sizeof(struct pollfd));
    memset(&state->sessions[idx], -1, sizeof(session_t));
}

int ctx_init(context_t *ctx, app_state_t *state, session_t *session)
{
    memset(ctx, 0, sizeof(context_t));
    ctx->state     = state;
    ctx->session   = session;
    ctx->client_fd = session->pollfd->fd;
    ctx->user_id   = session->user_id;

    return 0;
}

void ctx_destroy(context_t *ctx)
{
    FREE_IF_NOT_NULL(ctx->in_bytes);
    FREE_IF_NOT_NULL(ctx->out_bytes);
}
