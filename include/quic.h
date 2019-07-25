#ifndef QUIC_H_
#define QUIC_H_

#include <stdint.h>
#include <pcap.h>

typedef struct decode_var_len_data {
    u_char excessive_usable_bit;
    uint64_t value;
} decode_var_len_data;

decode_var_len_data quic_decode_var_len_int(u_char *header_field);
void quic_parse_header(const u_char *udp_payload, unsigned int payload_length,
    char *src_ip_port, char *dst_ip_port);

#endif