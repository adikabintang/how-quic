/*
TODO: this should be a unit test with cmocka. not like this.
 */

#include <stdio.h>
#include <inttypes.h>
#include "quic.h"

int main()
{
    uint64_t x;
    // test cases: https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16
    u_char header_field[] = {0x25};
    x = decode_var_len_int(header_field);
    printf("%" PRIu64 "\n", x);
    

    u_char header_field_1[] = {0x7b, 0xbd};
    x = decode_var_len_int(header_field_1);
    printf("%" PRIu64 "\n", x);

    u_char header_field_2[] = {0x9d, 0x7f, 0x3e, 0x7d};
    x = decode_var_len_int(header_field_2);
    printf("%" PRIu64 "\n", x);

    u_char header_field_3[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    x = decode_var_len_int(header_field_3);
    printf("%" PRIu64 "\n", x);
    return 0;
}