#ifndef QUIC_H_
#define QUIC_H_

#include <stdint.h>
#include <pcap.h>

// initial packet
// https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-17.2.2

typedef struct quic_long_header {
    u_char first_header;
    u_int version;
    u_char dcil_scil;
    // u_char *dst_conn_id;
    // u_char *src_conn_id;
} quic_long_header;

typedef struct decode_var_len_data {
    u_char excessive_usable_bit;
    uint64_t value;
} decode_var_len_data;

// https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16
decode_var_len_data quic_decode_var_len_int(u_char *header_field);
void quic_parse_header(const u_char *udp_payload, unsigned int payload_length);

/*
self note
---
possible code pattern:
factory object
input: Long packet type (bit 2-3 from header)
output: the right object if it is a quic initial packet, 0-rtt, handskare, retry
but....this is C! there is no base class. 

wait, see these: 
- https://stackoverflow.com/questions/3204511/factory-pattern-implementation-using-ansi-c
- https://github.com/huawenyu/Design-Patterns-in-C/blob/master/auto-gen/factory/simple_factory/pizza_simple_factory.h

*/

#endif