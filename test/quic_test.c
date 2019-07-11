/*
TODO: this should be a unit test with cmocka. not like this.
 */

#include <stdio.h>
#include "quic.h"

int main()
{
    // test cases: https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16
    //u_char header_field[] = {0x7b, 0xbd};
    u_char header_field[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    uint64_t x = decode_var_len_int(header_field);
    return 0;
}