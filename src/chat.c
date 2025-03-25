#include "chat.h"
#include "io.h"
#include "packets.h"
#include <arpa/inet.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_stdlib.h>
#include <string.h>

const funcMapping chat_func[] = {
    {CHT_Send,    chat_broadcast},
    {SYS_Success, NULL          }  // Null termination for safety
};

ssize_t chat_broadcast(context_t *ctx)
{
    // Iterate through all saved FDs...
    for(size_t idx = 1; idx < ctx->state->max_clients; idx++)
    {
        const int indexed_fd = ctx->state->pollfds[idx].fd;

        // ... Except for invalid clients and the sender client ...
        if(indexed_fd != -1 && indexed_fd != ctx->client_fd)
        {
            // ... Broadcast
            write_fully(indexed_fd, ctx->in_bytes, PACKET_CLIENT_HEADER_SIZE + ctx->in_header.payload_len, &ctx->err);
        }
    }

    // Indicate that no response should be sent
    free(ctx->out_bytes);
    ctx->out_bytes = NULL;

    return 0;
}
