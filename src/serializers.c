#include "serializers.h"
#include "ber.h"
#include "database.h"
#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int assert_packet_size(const char *packet_name, size_t expected_size, size_t actual_size);

// Serialization
size_t serialize_client_header(uint8_t **bytes, const packet_client_header_t *header)
{
    size_t offset = 0;

    serialize_1_byte(*bytes, &offset, header->packet_type);
    serialize_1_byte(*bytes, &offset, header->version);
    serialize_2_bytes(*bytes, &offset, header->sender_id);
    serialize_2_bytes(*bytes, &offset, header->payload_len);

    assert_packet_size("packet_client_header", PACKET_CLIENT_HEADER_SIZE, offset);

    return offset;
}

size_t serialize_sm_header(uint8_t **bytes, const packet_sm_header_t *header)
{
    size_t offset = 0;

    serialize_1_byte(*bytes, &offset, header->packet_type);
    serialize_1_byte(*bytes, &offset, header->version);
    serialize_2_bytes(*bytes, &offset, header->payload_len);

    assert_packet_size("packet_sm_header", PACKET_SM_HEADER_SIZE, offset);

    return offset;
}

size_t serialize_sys_success(uint8_t **bytes, const packet_sys_success_t *packet, int *err)
{
    packet_client_header_t header;

    // Define sizes of members
    // NOTE: sizeof(packet_*_t) is not reliable because padding could be introduced or pointers could
    // misrepresent the actual size of the data by returning the size of a (void*).
    const size_t size_packet_type = sizeof(packet->packet_type);
    const size_t payload_len      = (BER_SIZE + size_packet_type);

    size_t offset = 0;

    // Define header parameters
    memset(&header, 0, sizeof(packet_client_header_t));
    header.packet_type = PACKET_SYS_SUCCESS;
    header.version     = 1;
    header.sender_id   = packet->header != NULL ? packet->header->sender_id : SENDER_ID_DEFAULT;
    header.payload_len = (uint16_t)payload_len;

    // Allocate space for the serialized header and data
    errno  = 0;
    *bytes = (uint8_t *)calloc(PACKET_CLIENT_HEADER_SIZE + payload_len, sizeof(uint8_t));
    if(*bytes == NULL)
    {
        *err = errno;
        return 0;
    }

    // Serialize the header
    offset += serialize_client_header(bytes, &header);
    if(offset == 0)
    {
        return 0;
    }

    // Serialize the payload
    ber_sign_enumerated(*bytes, &offset, size_packet_type);
    serialize_1_byte(*bytes, &offset, packet->packet_type);

    // Check that sizes are as expected
    assert_packet_size("packet_sys_success", PACKET_CLIENT_HEADER_SIZE + payload_len, offset);

    return offset;
}

size_t serialize_sys_error(uint8_t **bytes, const packet_sys_error_t *packet, int *err)
{
    packet_client_header_t header;

    // Define sizes of members
    const size_t size_code    = sizeof(packet->code);
    const size_t size_message = strlen(packet->message);
    const size_t payload_len  = (BER_SIZE + size_code) + (BER_SIZE + size_message);

    size_t offset = 0;

    // NOTE: This is a limitation defined by the protocol
    if(payload_len > UINT16_MAX)
    {
        *err = ERANGE;
        return 0;
    }

    // Define header parameters
    memset(&header, 0, sizeof(packet_client_header_t));
    header.packet_type = PACKET_SYS_ERROR;
    header.version     = 1;
    header.sender_id   = packet->header != NULL ? packet->header->sender_id : SENDER_ID_DEFAULT;
    header.payload_len = (uint16_t)payload_len;

    // Allocate space for the serialized header and data
    errno  = 0;
    *bytes = (uint8_t *)calloc(PACKET_CLIENT_HEADER_SIZE + payload_len, sizeof(uint8_t));
    if(*bytes == NULL)
    {
        *err = errno;
        return 0;
    }

    // Serialize the header
    offset += serialize_client_header(bytes, &header);
    if(offset == 0)
    {
        return 0;
    }

    // Serialize the payload
    ber_sign_enumerated(*bytes, &offset, size_code);
    serialize_1_byte(*bytes, &offset, packet->code);

    // NOTE: There are two distinct BER string types: UTF8STRING and PRINTABLE_STRING. Assumably, the former does not terminate while the latter does.
    // TODO: Determine if `ber_sign_utf8_string` should handle removing the extra length (the single null term) off of `size_message` or if it should be handled on a case-by-case basis.
    ber_sign_utf8string(*bytes, &offset, size_message);
    serialize_1_byte_ptr(*bytes, &offset, (uint8_t *)packet->message, size_message);

    // Check that sizes are as expected
    assert_packet_size("packet_sys_error", PACKET_CLIENT_HEADER_SIZE + payload_len, offset);

    return offset;
}

size_t serialize_acc_login_success(uint8_t **bytes, const packet_acc_login_success_t *packet, int *err)
{
    packet_client_header_t header;

    // Define sizes of members
    const size_t size_id     = sizeof(packet->id);
    const size_t payload_len = (BER_SIZE + size_id);

    size_t offset = 0;

    // Define header parameters
    memset(&header, 0, sizeof(packet_client_header_t));
    header.packet_type = PACKET_ACC_LOGIN_SUCCESS;
    header.version     = 1;
    header.sender_id   = packet->header != NULL ? packet->header->sender_id : SENDER_ID_DEFAULT;
    header.payload_len = (uint16_t)payload_len;

    // Allocate space for the serialized header and data
    errno  = 0;
    *bytes = (uint8_t *)calloc(PACKET_CLIENT_HEADER_SIZE + payload_len, sizeof(uint8_t));
    if(*bytes == NULL)
    {
        *err = errno;
        return 0;
    }

    // Serialize the header
    offset += serialize_client_header(bytes, &header);
    if(offset == 0)
    {
        return 0;
    }

    // Serialize the payload
    ber_sign_integer(*bytes, &offset, size_id);
    serialize_2_bytes(*bytes, &offset, packet->id);

    // Check that sizes are as expected
    assert_packet_size("packet_acc_login_success", PACKET_CLIENT_HEADER_SIZE + payload_len, offset);

    return offset;
}

// Deserialization
size_t deserialize_client_header(packet_client_header_t *header, const uint8_t *bytes)
{
    size_t offset = 0;

    memset(header, 0, sizeof(packet_client_header_t));
    header->packet_type = deserialize_1_byte(bytes, &offset);
    header->version     = deserialize_1_byte(bytes, &offset);
    header->sender_id   = deserialize_2_bytes(bytes, &offset);
    header->payload_len = deserialize_2_bytes(bytes, &offset);

    return offset;
}

size_t deserialize_acc_login(packet_acc_login_t *packet, const uint8_t *bytes)
{
    packet_client_header_t *header;
    ber_t                   ber;

    size_t offset = 0;

    // Create heap allocated header
    header = (packet_client_header_t *)calloc(1, sizeof(packet_client_header_t));
    if(header == NULL)
    {
        perror("deserialize_sys_error::calloc");
        return 0;
    }

    // Deserialize header
    offset += deserialize_client_header(header, bytes);
    packet->header = header;

    // Deserialize body
    ber_decode(&ber, bytes, &offset);
    packet->username = deserialize_string_ptr(bytes, &offset, ber.length);

    ber_decode(&ber, bytes, &offset);
    packet->password = deserialize_string_ptr(bytes, &offset, ber.length);

    return offset;
}

size_t deserialize_acc_logout(packet_acc_logout_t *packet, const uint8_t *bytes)
{
    packet_client_header_t *header;

    size_t offset = 0;

    // Create heap allocated header
    header = (packet_client_header_t *)calloc(1, sizeof(packet_client_header_t));
    if(header == NULL)
    {
        perror("deserialize_sys_error::calloc");
        return 0;
    }

    // Deserialize header
    offset += deserialize_client_header(header, bytes);
    packet->header = header;

    // Deserialize body (empty)

    return offset;
}

size_t deserialize_acc_create(packet_acc_create_t *packet, const uint8_t *bytes)
{
    packet_client_header_t *header;
    ber_t                   ber;

    size_t offset = 0;

    // Create heap allocated header
    header = (packet_client_header_t *)calloc(1, sizeof(packet_client_header_t));
    if(header == NULL)
    {
        perror("deserialize_acc_create::calloc");
        return 0;
    }

    // Deserialize header
    offset += deserialize_client_header(header, bytes);
    packet->header = header;

    // Deserialize body
    ber_decode(&ber, bytes, &offset);
    packet->username = deserialize_string_ptr(bytes, &offset, ber.length);

    ber_decode(&ber, bytes, &offset);
    packet->password = deserialize_string_ptr(bytes, &offset, ber.length);

    return offset;
}

size_t deserialize_acc_edit(packet_acc_edit_t *packet, const uint8_t *bytes)
{
    packet_client_header_t *header;
    ber_t                   ber;

    size_t offset = 0;

    // Create heap allocated header
    header = (packet_client_header_t *)calloc(1, sizeof(packet_client_header_t));
    if(header == NULL)
    {
        perror("deserialize_acc_edit::calloc");
        return 0;
    }

    // Deserialize header
    offset += deserialize_client_header(header, bytes);
    packet->header = header;

    // Deserialize body
    offset += BER_SIZE;
    packet->edit_field = deserialize_1_byte(bytes, &offset);

    ber_decode(&ber, bytes, &offset);
    packet->edit_value = deserialize_string_ptr(bytes, &offset, ber.length);

    return offset;
}

size_t deserialize_cht_send(packet_cht_send_t *packet, const uint8_t *bytes)
{
    packet_client_header_t *header;
    ber_t                   ber;

    size_t offset = 0;

    // Create heap allocated header
    header = (packet_client_header_t *)calloc(1, sizeof(packet_client_header_t));
    if(header == NULL)
    {
        perror("deserialize_cht_send::calloc");
        return 0;
    }

    // Deserialize header
    offset += deserialize_client_header(header, bytes);
    packet->header = header;

    // Deserialize body
    ber_decode(&ber, bytes, &offset);
    packet->generalized_time = deserialize_string_ptr(bytes, &offset, ber.length);

    ber_decode(&ber, bytes, &offset);
    packet->content = deserialize_string_ptr(bytes, &offset, ber.length);

    ber_decode(&ber, bytes, &offset);
    packet->username = deserialize_string_ptr(bytes, &offset, ber.length);

    return offset;
}

// ==========
//  Database
// ==========
// size_t serialize_table_metadata(uint8_t **bytes, const db_table_metadata_t *metadata)
// {
//     size_t offset = 0;
//
//     serialize_4_bytes(*bytes, &offset, (uint32_t)metadata->count);
//     serialize_4_bytes(*bytes, &offset, (uint32_t)metadata->columns);
//     serialize_4_bytes(*bytes, &offset, (uint32_t)metadata->ent_size);
//
//     assert_packet_size("db_table_metadata", DATABASE_TABLE_METADATA_SIZE, offset);
//
//     return offset;
// }
//
// size_t serialize_user_entity(uint8_t **bytes, const db_user_entity_t *entity, int *err)
// {
//     db_table_metadata_t metadata;
//
//     // Define sizes of members
//     const size_t size_username = strlen(entity->username);
//     const size_t size_password = strlen(entity->password);
//     const size_t ent_size      = (BER_SIZE + size_username) + (BER_SIZE + size_password);
//
//     size_t offset = 0;
//
//     // NOTE: This is a limitation defined by the protocol
//     if(ent_size > UINT16_MAX)
//     {
//         *err = ERANGE;
//         return 0;
//     }
//
//     // Define header parameters -- This is to ensure the metadata is always correct
//     // in the cases where an empty entity is passed in
//     memset(&metadata, 0, sizeof(db_table_metadata_t));
//     metadata.columns  = 2;
//     metadata.ent_size = ent_size;
//
//     // Allocate space for the serialized header and data
//     errno  = 0;
//     *bytes = (uint8_t *)calloc(DATABASE_TABLE_METADATA_SIZE + ent_size, sizeof(uint8_t));
//     if(*bytes == NULL)
//     {
//         *err = errno;
//         return 0;
//     }
//
//     // Serialize the table metadata
//     offset += serialize_table_metadata(bytes, &metadata);
//     if(offset == 0)
//     {
//         return 0;
//     }
//
//     // Serialize the columns
//     ber_sign_utf8string(*bytes, &offset, size_username);
//     serialize_1_byte_ptr(*bytes, &offset, (uint8_t *)entity->username, size_username);
//
//     ber_sign_utf8string(*bytes, &offset, size_password);
//     serialize_1_byte_ptr(*bytes, &offset, (uint8_t *)entity->password, size_password);
//
//     // Check that sizes are as expected
//     assert_packet_size("db_user_entity", DATABASE_TABLE_METADATA_SIZE + ent_size, offset);
//
//     return offset;
// }
//
// // Deserialize
//
// size_t deserialize_table_metadata(db_table_metadata_t *metadata, const uint8_t *bytes)
// {
//     size_t offset = 0;
//
//     memset(metadata, 0, sizeof(db_table_metadata_t));
//     metadata->count    = deserialize_4_bytes(bytes, &offset);
//     metadata->columns  = deserialize_4_bytes(bytes, &offset);
//     metadata->ent_size = deserialize_4_bytes(bytes, &offset);
//
//     return offset;
// }
//
// size_t deserialize_user_entity(db_user_entity_t *entity, const uint8_t *bytes)
// {
//     db_table_metadata_t *metadata;
//     ber_t                ber;
//
//     size_t offset = 0;
//
//     // Create heap allocated table metadata
//     metadata = (db_table_metadata_t *)calloc(1, sizeof(db_table_metadata_t));
//     if(metadata == NULL)
//     {
//         perror("deserialize_user_entity::calloc");
//         return 0;
//     }
//
//     // Deserialize the table metadata
//     offset += deserialize_table_metadata(metadata, bytes);
//     memcpy(&entity->metadata, metadata, offset);
//
//     // Deserialize the columns
//     ber_decode(&ber, bytes, &offset);
//     entity->username = deserialize_string_ptr(bytes, &offset, ber.length);
//
//     ber_decode(&ber, bytes, &offset);
//     entity->password = deserialize_string_ptr(bytes, &offset, ber.length);
//
//     free(metadata);
//     return offset;
// }

// =========================
//  Utilities/Serialization
// =========================
void serialize_1_byte(uint8_t *bytes, size_t *offset, uint8_t data)
{
    bytes[*offset] = data;
    *offset += sizeof(data);
}

void serialize_2_bytes(uint8_t *bytes, size_t *offset, uint16_t data)
{
    uint16_t network_order;

    network_order = htons(data);
    memcpy(&bytes[*offset], &network_order, sizeof(data));
    *offset += sizeof(data);
}

void serialize_4_bytes(uint8_t *bytes, size_t *offset, uint32_t data)
{
    uint32_t network_order;

    network_order = htonl(data);
    memcpy(&bytes[*offset], &network_order, sizeof(data));
    *offset += sizeof(data);
}

void serialize_1_byte_ptr(uint8_t *bytes, size_t *offset, const uint8_t *data, size_t nelements)
{
    for(size_t idx = 0; idx < nelements; idx++)
    {
        serialize_1_byte(bytes, offset, data[idx]);
    }
}

void serialize_2_bytes_ptr(uint8_t *bytes, size_t *offset, const uint8_t *data, size_t nelements)
{
    for(size_t idx = 0; idx < nelements; idx++)
    {
        serialize_2_bytes(bytes, offset, data[idx]);
    }
}

void serialize_4_bytes_ptr(uint8_t *bytes, size_t *offset, const uint8_t *data, size_t nelements)
{
    for(size_t idx = 0; idx < nelements; idx++)
    {
        serialize_4_bytes(bytes, offset, data[idx]);
    }
}

// ===========================
//  Utilities/Deserialization
// ===========================
uint8_t deserialize_1_byte(const uint8_t *bytes, size_t *offset)
{
    uint8_t ddata;    // deserialized data

    ddata = bytes[*offset];
    *offset += 1;

    return ddata;
}

uint16_t deserialize_2_bytes(const uint8_t *bytes, size_t *offset)
{
    uint16_t ddata;

    memcpy(&ddata, &bytes[*offset], sizeof(uint16_t));
    ddata = ntohs(ddata);
    *offset += sizeof(uint16_t);

    return ddata;
}

uint32_t deserialize_4_bytes(const uint8_t *bytes, size_t *offset)
{
    uint32_t ddata;

    memcpy(&ddata, &bytes[*offset], sizeof(uint32_t));
    ddata = ntohl(ddata);
    *offset += sizeof(uint32_t);

    return ddata;
}

char *deserialize_string_ptr(const uint8_t *bytes, size_t *offset, size_t nelements)
{
    char *ptrbuf;

    errno  = 0;
    ptrbuf = (char *)calloc(nelements + 1, sizeof(char));
    if(ptrbuf == NULL)
    {
        perror("deserialize_1_byte_ptr::calloc");
        return NULL;
    }

    for(size_t idx = 0; idx < nelements; idx++)
    {
        ptrbuf[idx] = (char)deserialize_1_byte(bytes, offset);
    }

    // Should the type be still uint8_t and casted to char* or changed to char* immediately? Is there a real difference?
    return ptrbuf;
}

uint8_t *deserialize_1_byte_ptr(const uint8_t *bytes, size_t *offset, size_t nelements)
{
    uint8_t *ptrbuf;

    errno  = 0;
    ptrbuf = (uint8_t *)calloc(nelements, sizeof(uint8_t));
    if(ptrbuf == NULL)
    {
        perror("deserialize_1_byte_ptr::calloc");
        return NULL;
    }

    for(size_t idx = 0; idx < nelements; idx++)
    {
        ptrbuf[idx] = deserialize_1_byte(bytes, offset);
    }

    return ptrbuf;
}

uint16_t *deserialize_2_bytes_ptr(const uint8_t *bytes, size_t *offset, size_t nelements)
{
    uint16_t *ptrbuf;

    errno  = 0;
    ptrbuf = (uint16_t *)calloc(nelements, sizeof(uint16_t));
    if(ptrbuf == NULL)
    {
        perror("deserialize_2_bytes_ptr::calloc");
        return NULL;
    }

    for(size_t idx = 0; idx < nelements; idx++)
    {
        const uint16_t ddata = deserialize_2_bytes(bytes, offset);
        memcpy(ptrbuf + idx, &ddata, sizeof(uint16_t));
    }

    return ptrbuf;
}

uint32_t *deserialize_4_bytes_ptr(const uint8_t *bytes, size_t *offset, size_t nelements)
{
    uint32_t *ptrbuf;

    errno  = 0;
    ptrbuf = (uint32_t *)calloc(nelements, sizeof(uint32_t));
    if(ptrbuf == NULL)
    {
        perror("deserialize_4_bytes_ptr::calloc");
        return NULL;
    }

    for(size_t idx = 0; idx < nelements; idx++)
    {
        const uint32_t ddata = deserialize_4_bytes(bytes, offset);
        memcpy(ptrbuf + idx, &ddata, sizeof(uint32_t));
    }

    return ptrbuf;
}

// ===========================
//  Utilities/Other
// ===========================
static int assert_packet_size(const char *packet_name, size_t expected_size, size_t actual_size)
{
    if(packet_name == NULL)
    {
        fprintf(stderr, "assert_packet_size: packet_name must be given.\n");
        return -2;
    }

    if(expected_size == 0 || actual_size == 0)
    {
        fprintf(stderr, "assert_packet_size: expected_size and actual_size must be greater than 0.\n");
    }

    if(actual_size != expected_size)
    {
        fprintf(stderr, "Warning: sizeof(%s) does not match actual %s struct size.\n", packet_name, packet_name);
        return -3;
    }

    return 0;
}
