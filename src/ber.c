#include "ber.h"
#include <stdint.h>
#include <stdio.h>

static size_t ber_sign(uint8_t *buf, size_t *offset, uint8_t tag, uint8_t len);

size_t ber_sign_boolean(uint8_t *buf, size_t *offset)
{
    return ber_sign(buf, offset, BER_BOOLEAN, 1);
}

size_t ber_sign_integer(uint8_t *buf, size_t *offset, size_t len)
{
    if(len > UINT8_MAX)
    {
        fprintf(stderr, "ber_sign_integer::len: Integer length is longer than is acceptable.\n");
        return 0;
    }

    return ber_sign(buf, offset, BER_INTEGER, (uint8_t)len);
}

size_t ber_sign_enumerated(uint8_t *buf, size_t *offset, size_t len)
{
    if(len > UINT8_MAX)
    {
        fprintf(stderr, "ber_sign_enumerated::len: Data length is longer than is acceptable.\n");
        return 0;
    }

    return ber_sign(buf, offset, BER_ENUMERATED, (uint8_t)len);
}

size_t ber_sign_utf8string(uint8_t *buf, size_t *offset, size_t len)
{
    if(len > UINT8_MAX)
    {
        fprintf(stderr, "ber_sign_utf8string::len: String is longer than is acceptable.\n");
        return 0;
    }

    return ber_sign(buf, offset, BER_UTF8STRING, (uint8_t)len);
}

size_t ber_sign_printable_string(uint8_t *buf, size_t *offset, size_t len)
{
    if(len > UINT8_MAX)
    {
        fprintf(stderr, "ber_sign_printable_string::len: String is longer than is acceptable.\n");
        return 0;
    }

    return ber_sign(buf, offset, BER_PRINTABLE_STRING, (uint8_t)len);
}

size_t ber_sign_utc_time(uint8_t *buf, size_t *offset, size_t len)
{
    if(len > UINT8_MAX)
    {
        fprintf(stderr, "ber_sign_utc_time::len: String is longer than is acceptable.\n");
        return 0;
    }

    return ber_sign(buf, offset, BER_UTC_TIME, (uint8_t)len);
}

size_t ber_sign_generalized_time(uint8_t *buf, size_t *offset, size_t len)
{
    if(len > UINT8_MAX)
    {
        fprintf(stderr, "ber_sign_generalized_time::len: String is longer than is acceptable.\n");
        return 0;
    }

    return ber_sign(buf, offset, BER_GENERALIZED_TIME, (uint8_t)len);
}

static size_t ber_sign(uint8_t *buf, size_t *offset, uint8_t tag, uint8_t len)
{
    const size_t base = *offset;

    buf[*offset] = tag;
    *offset += sizeof(tag);

    buf[*offset] = len;
    *offset += sizeof(len);

    return *offset - base;
}

size_t ber_decode(ber_t *ber, const uint8_t *data, size_t *offset)
{
    const size_t base = *offset;

    ber->tag = data[*offset];
    *offset += sizeof(ber->tag);

    ber->length = data[*offset];
    *offset += sizeof(ber->length);

    return *offset - base;
}
