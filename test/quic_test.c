#include <criterion/criterion.h>

#include "quic.h"

Test(quic_decode_var_len_int, test) {
    decode_var_len_data d;

    u_char header_field[] = {0x25};
    d = quic_decode_var_len_int(header_field);
    cr_assert(d.value == 37);
    cr_assert(d.excessive_usable_bit == 6);

    u_char header_field_1[] = {0x7b, 0xbd};
    d = quic_decode_var_len_int(header_field_1);
    cr_assert(d.value == 15293);
    cr_assert(d.excessive_usable_bit == 14);

    u_char header_field_2[] = {0x9d, 0x7f, 0x3e, 0x7d};
    d = quic_decode_var_len_int(header_field_2);
    cr_assert(d.value == 494878333);
    cr_assert(d.excessive_usable_bit == 30);

    u_char header_field_3[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
    d = quic_decode_var_len_int(header_field_3);
    cr_assert(d.value == 151288809941952652);
    cr_assert(d.excessive_usable_bit == 62);

    u_char h[] = {0x44, 0xcb};
    d = quic_decode_var_len_int(h);
    cr_assert(d.value == 1227);
    cr_assert(d.excessive_usable_bit == 14);
}