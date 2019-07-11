#include "quic.h"

uint64_t decode_var_len_int(u_char *header_field)
{
    uint8_t var_len = 0;
    uint64_t value = 0;
    uint8_t usable_bit = 0;

    // assuming big endian
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

    // printf("usable bit: %d\n", usable_bit);

    u_char *hdr_pointer = header_field;
    value = *hdr_pointer & 0b00111111;
    usable_bit -= 6;
    // printf("v: %x\n", value);

    while (usable_bit > 0) {
        // printf("usable bit: %d\n", usable_bit);
        hdr_pointer += 1;
        value = (value << 8) & 0xFFFFFFFFFFFFFFFF;
        // printf("v> %x\n", value);
        // printf("h: %x\n", *hdr_pointer);
        value = value | *hdr_pointer;
        // printf("v? %x\n", value);
        usable_bit = usable_bit - 8;
    }
    
    // printf("%x\n", var_len);
    return value;
}