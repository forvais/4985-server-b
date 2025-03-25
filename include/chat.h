#ifndef CHAT_H
#define CHAT_H

#include "messaging.h"
#include "state.h"

extern const funcMapping chat_func[];

ssize_t chat_broadcast(context_t *ctx);

#endif    // CHAT_H
