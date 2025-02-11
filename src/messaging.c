#include "../include/messaging.h"
#include "../include/utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ERR_READ (-5)




void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for(size_t i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int deserialize_header(header_t *header, const uint8_t *buf)
{
    size_t offset;

    uint8_t  type;
    uint8_t  version;
    uint16_t sender_id;
    uint16_t payload_len;

    offset = 0;

    type = buf[offset];
    offset += 1;

    version = buf[offset];
    offset += 1;

    memcpy(&sender_id, buf + offset, sizeof(uint16_t));
    sender_id = ntohs(sender_id);
    offset += sizeof(uint16_t);

    memcpy(&payload_len, buf + offset, sizeof(uint16_t));
    payload_len = ntohs(payload_len);

    if(header == NULL)
    {
        return -1;
    }

    memset(header, 0, sizeof(header_t));
    header->type        = type;
    header->version     = version;
    header->sender_id   = sender_id;
    header->payload_len = payload_len;

    return 0;
}


ssize_t read_packet(int fd, uint8_t **buf, header_t *header, int *err)
{
    size_t   header_len = sizeof(header_t);
    uint16_t payload_len;
    ssize_t  nread;
    header_t temp_header;
    uint8_t *newbuf;
    uint8_t *payload = NULL;

    *buf = (uint8_t *)calloc(header_len, sizeof(uint8_t));
    if(!*buf)
    {
        return -1;
    }

    // Read header
    errno = 0;
    nread = read(fd, *buf, header_len);
    if(nread < 0)
    {
        *err = errno;
        perror("read_packet::read");
        free(*buf);
        return -1;
    }

    print_hex("raw data recieved", *buf, header_len);

    // Deserialize header

    if(deserialize_header(&temp_header, *buf) < 0)
    {
        fprintf(stderr, "read_packet::deserialize_header: Failed to deserialize header.\n");
        free(*buf);
        return -3;
    }

    // Get payload size
    payload_len = temp_header.payload_len;

    // Allocate memory for full message
    newbuf = (uint8_t *)realloc(*buf, header_len + payload_len);
    if(!newbuf)
    {
        perror("read_packet::realloc");
        free(*buf);
        return -4;
    }
    *buf = newbuf;

    // Read payload
    errno = 0;
    nread = read(fd, *buf + header_len, payload_len);
    if(nread < 0)
    {
        *err = errno;
        perror("read_packet::read");
        free(*buf);
        return ERR_READ;
    }

    print_hex("raw payload recieved", *buf + header_len, payload_len);

    // Deserialize full packet

    if(deserialize_packet(*buf, header_len + payload_len, header, &payload) < 0)
    {
        fprintf(stderr, "read_packet::deserialize_packet: Failed to deserialize packet.\n");
        free(*buf);

        if(payload)
        {
            free(payload);
        }

        return ERR_READ;
    }

    printf("Packet succssfully read\n");

    free(payload);

    return (ssize_t)header_len + payload_len;
}

void serialize_packet(const header_t *header, const uint8_t *payload, uint8_t **buffer, size_t *buf_size)
{
    size_t   header_size;
    size_t   payload_size;
    header_t net_header;

    if(!header || !buffer || !buf_size)
    {
        return;
    }

    net_header.type        = header->type;
    net_header.version     = header->version;
    net_header.sender_id   = htons(header->sender_id);
    net_header.payload_len = htons(header->payload_len);

    header_size  = sizeof(header_t);
    payload_size = header->payload_len;

    *buf_size = header_size + payload_size;
    *buffer   = (uint8_t *)malloc(*buf_size);
    if(!*buffer)
    {
        perror("malloc failed");
        return;
    }

    memcpy(*buffer, &net_header, header_size);

    if(payload_size > 0 && payload)
    {
        memcpy(*buffer + header_size, payload, payload_size);
    }

    print_hex("serialzed packet", *buffer, *buf_size);
}

int deserialize_packet(const uint8_t *buffer, size_t buf_size, header_t *header, uint8_t **payload)
{
    size_t payload_size;
    if(!buffer || !header || !payload || buf_size < sizeof(header_t))
    {
        return -1;
    }

    *payload = NULL;

    memcpy(header, buffer, sizeof(header_t));

    header->sender_id   = ntohs(header->sender_id);
    header->payload_len = ntohs(header->payload_len);

    payload_size = header->payload_len;
    if(payload_size > 0 && buf_size >= sizeof(header_t) + payload_size)
    {
        *payload = (uint8_t *)malloc(payload_size + 1);
        if(!*payload)
        {
            perror("malloc failed at deserialize");
            return -1;
        }
        memcpy(*payload, buffer + sizeof(header_t), payload_size);
        (*payload)[payload_size] = '\0';
    }

    return 0;
}

ssize_t send_packet(int fd, const header_t *header, const uint8_t *payload)
{
    uint8_t *buffer = {0};
    size_t   buf_size;
    ssize_t  bytes_sent;

    serialize_packet(header, payload, &buffer, &buf_size);
    if(!buffer)
    {
        return -1;
    }

    bytes_sent = write(fd, buffer, buf_size);
    if(bytes_sent < 0)
    {
        perror("write failed. cannot send packet");
    }
    printf("Sent %ld bytes]\n", bytes_sent);

    free(buffer);
    return bytes_sent;
}
