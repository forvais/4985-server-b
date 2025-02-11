// cppcheck-suppress-file unusedStructMember

#ifndef MESSAGING_H
#define MESSAGING_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/* TODO: THESE SHOULD NOT BE HERE, ONLY FOR DEMO */
typedef struct
{
    uint8_t  type;
    uint8_t  version;
    uint16_t sender_id;
    uint16_t payload_len;
} header_t;

/* TODO: THESE SHOULD NOT BE HERE, ONLY FOR DEMO */

void serialize_packet(const header_t *header, const uint8_t *payload, uint8_t **buffer, size_t *buf_size);
int  deserialize_packet(const uint8_t *buffer, size_t buf_size, header_t *header, uint8_t **payload);

ssize_t read_packet(int fd, uint8_t **buf, header_t *header, int *err);
ssize_t send_packet(int fd, const header_t *header, const uint8_t *payload);

void print_hex(const char *label, const uint8_t *data, size_t len);

#endif
