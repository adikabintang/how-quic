#include <criterion/criterion.h>

#include "quic.h"

Test(quic_decode_var_len_int, test) {
    u_char header_field[] = {0x25};
    cr_assert(quic_decode_var_len_int(header_field) == 37);

    u_char header_field_1[] = {0x7b, 0xbd};
    cr_assert(quic_decode_var_len_int(header_field_1) == 15293);

    u_char header_field_2[] = {0x9d, 0x7f, 0x3e, 0x7d};
    cr_assert(quic_decode_var_len_int(header_field_2) == 494878333);

    u_char header_field_3[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    cr_assert(quic_decode_var_len_int(header_field_3) == 151288809941952652);

    u_char h[] = {0x44, 0xcb};
    cr_assert(quic_decode_var_len_int(h) == 1227);
}