#include "quic.h"

uint64_t decode_var_len_int(u_char *header_field)
{
    int var_len;
    // assuming big endian
    var_len = (*header_field & 0b11000000) >> 6;
    printf("%x", var_len);
    return 0;
}