#include "quic.h"

/*
must be host format. use ntohs() to convert.
 */
uint64_t decode_var_len_int(u_char *header_field)
{
    uint8_t var_len = 0;
    uint64_t value = 0;
    uint8_t usable_bit = 0;

    var_len = (*header_field & 0b11000000) >> 6;
    switch (var_len)
    {
    case 0b00:
        usable_bit = 6;
        break;
    case 0b01:
        usable_bit = 14;
        break;
    case 0b10:
        usable_bit = 30;
        break;
    case 0b11:
        usable_bit = 62;
        break;
    default:
        break;
    }

    u_char *hdr_pointer = header_field;
    value = *hdr_pointer & 0b00111111;
    usable_bit -= 6;
    
    while (usable_bit > 0) {
        value = (value << 8) & 0xFFFFFFFFFFFFFFFF;
        hdr_pointer++;
        value |= *hdr_pointer;
        usable_bit -= 8;
    }
    
    return value;
}