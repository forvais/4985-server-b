// cppcheck-suppress-file unusedStructMember

#ifndef BER_H
#define BER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define BER_SIZE 2

typedef enum
{
    BER_BOOLEAN          = 1,
    BER_INTEGER          = 2,
    BER_NULL             = 5,
    BER_ENUMERATED       = 10,
    BER_UTF8STRING       = 12,
    BER_SEQUENCE         = 16,
    BER_SEQUENCE_OF      = 48,
    BER_PRINTABLE_STRING = 19,
    BER_UTC_TIME         = 23,
    BER_GENERALIZED_TIME = 24,
} BER;

typedef struct
{
    uint8_t tag;
    uint8_t length;
} ber_t;

size_t ber_sign_boolean(uint8_t *buf, size_t *offset);
size_t ber_sign_integer(uint8_t *buf, size_t *offset, size_t len);
// size_t ber_sign_null(uint8_t *buf, size_t *offset); // TODO: Determine length of NULL, 1 byte? 4 bytes?
size_t ber_sign_enumerated(uint8_t *buf, size_t *offset, size_t len);
size_t ber_sign_utf8string(uint8_t *buf, size_t *offset, size_t len);
// size_t ber_sign_sequence(uint8_t *buf, size_t *offset, /* ??? */);
// size_t ber_sign_sequence_of(uint8_t *buf, size_t *offset, /* ??? */);
size_t ber_sign_printable_string(uint8_t *buf, size_t *offset, size_t len);
size_t ber_sign_utc_time(uint8_t *buf, size_t *offset, size_t len);
size_t ber_sign_generalized_time(uint8_t *buf, size_t *offset, size_t len);

size_t ber_decode(ber_t *ber, const uint8_t *data, size_t *offset);

// size_t ber_decode_boolean(ber_t *ber, uint8_t *data);
// size_t ber_decode_integer(ber_t *ber, uint8_t *data);
// size_t ber_decode_null(ber_t *ber, uint8_t *data);
// size_t ber_decode_enumerated(ber_t *ber, uint8_t *data);
// size_t ber_decode_utf8string(ber_t *ber, const uint8_t *data);
// // size_t ber_decode_sequence(ber_t* ber, uint8_t *data);
// // size_t ber_decode_sequence_of(ber_t* ber, uint8_t *data);
// size_t ber_decode_printable_string(ber_t *ber, uint8_t *data);
// size_t ber_decode_utc_time(ber_t *ber, uint8_t *data);
// size_t ber_decode_generalized_time(ber_t *ber, uint8_t *data);

#endif
