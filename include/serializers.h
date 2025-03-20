#ifndef SERIALIZERS_H
#define SERIALIZERS_H

#include "packets.h"

// Client/Server
size_t serialize_client_header(uint8_t **bytes, const packet_client_header_t *header);
size_t serialize_sm_header(uint8_t **bytes, const packet_sm_header_t *header);
size_t serialize_sys_success(uint8_t **bytes, const packet_sys_success_t *packet, int *err);
size_t serialize_sys_error(uint8_t **bytes, const packet_sys_error_t *packet, int *err);
size_t serialize_acc_login_success(uint8_t **bytes, const packet_acc_login_success_t *packet, int *err);
size_t serialize_svr_diagnostic(uint8_t **bytes, const packet_svr_diagnostic_t *packet, int *err);

size_t deserialize_client_header(packet_client_header_t *header, const uint8_t *bytes);
size_t deserialize_sm_header(packet_sm_header_t *header, const uint8_t *bytes);
size_t deserialize_acc_login(packet_acc_login_t *packet, const uint8_t *bytes);
size_t deserialize_acc_logout(packet_acc_logout_t *packet, const uint8_t *bytes);
size_t deserialize_acc_create(packet_acc_create_t *packet, const uint8_t *bytes);
size_t deserialize_acc_edit(packet_acc_edit_t *packet, const uint8_t *bytes);
size_t deserialize_cht_send(packet_cht_send_t *packet, const uint8_t *bytes);

// Database
// size_t serialize_table_metadata(uint8_t **bytes, const db_table_metadata_t *metadata);
// size_t serialize_user_entity(uint8_t **bytes, const db_user_entity_t *entity, int *err);
//
// size_t deserialize_table_metadata(db_table_metadata_t *metadata, const uint8_t *bytes);
// size_t deserialize_user_entity(db_user_entity_t *entity, const uint8_t *bytes);

void serialize_1_byte(uint8_t *bytes, size_t *offset, uint8_t data);
void serialize_2_bytes(uint8_t *bytes, size_t *offset, uint16_t data);
void serialize_4_bytes(uint8_t *bytes, size_t *offset, uint32_t data);
void serialize_1_byte_ptr(uint8_t *bytes, size_t *offset, const uint8_t *data, size_t nelements);
void serialize_2_bytes_ptr(uint8_t *bytes, size_t *offset, const uint8_t *data, size_t nelements);
void serialize_4_bytes_ptr(uint8_t *bytes, size_t *offset, const uint8_t *data, size_t nelements);

uint8_t   deserialize_1_byte(const uint8_t *bytes, size_t *offset);
uint16_t  deserialize_2_bytes(const uint8_t *bytes, size_t *offset);
uint32_t  deserialize_4_bytes(const uint8_t *bytes, size_t *offset);
char     *deserialize_string_ptr(const uint8_t *bytes, size_t *offset, size_t nelements);
uint8_t  *deserialize_1_byte_ptr(const uint8_t *bytes, size_t *offset, size_t nelements);
uint16_t *deserialize_2_bytes_ptr(const uint8_t *bytes, size_t *offset, size_t nelements);
uint32_t *deserialize_4_bytes_ptr(const uint8_t *bytes, size_t *offset, size_t nelements);

#endif
