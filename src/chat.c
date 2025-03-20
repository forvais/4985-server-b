#include "chat.h"
#include "io.h"
#include <arpa/inet.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_stdlib.h>
#include <string.h>

const funcMapping chat_func[] = {
    {CHT_Send,    chat_broadcast},
    {SYS_Success, NULL          }  // Null termination for safety
};

ssize_t chat_broadcast(request_t *request)
{
    // Broadcast the msg to all users
    request->response_len = (uint16_t)request->len + HEADER_SIZE;
    memcpy(request->response, request->content, request->response_len);    // The message out is the same as message in, copy the contents to the response

    // Iterate through all saved FDs and broadcast
    for(int i = 1; i < MAX_FDS; i++)
    {
        if(request->fds[i].fd != -1)
        {
            printf("broadcasting... %d\n", request->fds[i].fd);
            write_fully(request->fds[i].fd, request->response, (ssize_t)request->response_len, &request->err);
        }
    }

    return 0;
}
