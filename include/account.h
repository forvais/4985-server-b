#ifndef ACCOUNT_H
#define ACCOUNT_H

#include "messaging.h"
#include "state.h"

extern const funcMapping acc_func[];

ssize_t account_create(context_t *ctx);
ssize_t account_login(context_t *ctx);
ssize_t account_logout(context_t *ctx);
ssize_t account_edit(context_t *ctx);

#endif    // ACCOUNT_H
