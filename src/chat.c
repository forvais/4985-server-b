#include "chat.h"
#include "io.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_stdlib.h>
#include <string.h>

static ssize_t chat_broadcast(request_t *request);

const funcMapping chat_func[] = {
    {CHT_Send,    chat_broadcast},
    {SYS_Success, NULL          }  // Null termination for safety
};

static ssize_t chat_broadcast(request_t *request)
{
    char       *ptr;
    const char *timestamp;
    const char *content;
    const char *username;
    uint8_t     time_len;
    uint8_t     content_len;
    uint8_t     user_len;

    PRINT_VERBOSE("in chat_broadcast %d \n", request->client->fd);
    PRINT_DEBUG("sender_id %d \n", request->sender_id);
    PRINT_DEBUG("session_id %d \n", *request->session_id);

    if(request->sender_id != *request->session_id)
    {
        request->code = INVALID_REQUEST;
        return -1;
    }

    // broadcast
    // start from timestamp len
    ptr = (char *)request->content + HEADER_SIZE + 1;

    memcpy(&time_len, ptr, sizeof(time_len));
    ptr += sizeof(time_len);

    timestamp = ptr;

    // start from content len
    ptr += time_len + 1;
    memcpy(&content_len, ptr, sizeof(content_len));
    ptr += sizeof(content_len);

    content = ptr;

    // start from user len
    ptr += content_len + 1;
    memcpy(&user_len, ptr, sizeof(user_len));
    ptr += sizeof(user_len);

    username = ptr;

    printf("timestamp: %.*s\n", (int)time_len, timestamp);
    printf("content: %.*s\n", (int)content_len, content);
    printf("username: %.*s\n", (int)user_len, username);

    request->response_len = (uint16_t)(HEADER_SIZE + request->len);
    printf("response_len: %d\n", request->response_len);
    memcpy(request->response, request->content, request->response_len);

    msg_count++;
    printf("msg_count: %d\n", (int)msg_count);

    for(int i = 1; i < MAX_FDS; i++)
    {
        if(request->fds[i].fd != -1)
        {
            printf("broadcasting... %d\n", request->fds[i].fd);
            write_fully(request->fds[i].fd, request->response, request->response_len, &request->err);
        }
    }

    request->response_len = 0;

    return 0;
}
