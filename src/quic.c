#include "quic.h"
#include "log.h"
#include <netinet/in.h>
#include <netinet/if_ether.h>

/*
must be host format. use ntohs() to convert.
 */
uint64_t quic_decode_var_len_int(u_char *header_field)
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

    while (usable_bit > 0)
    {
        value = (value << 8);
        hdr_pointer++;
        value |= *hdr_pointer;
        usable_bit -= 8;
    }

    return value;
}

void quic_parse_header(const u_char *udp_payload)
{
    unsigned int counter_pointer = 0;
    unsigned int i;
    u_short header_format = ntohs(*udp_payload);
    counter_pointer++;

    log_debug(" quic header format: %x", header_format);
    u_short x = header_format & 0x8000;

    if (x == 0x8000)
    {
        log_debug(" quic: long header");
    }
    else
    {
        log_debug(" quic: short header");
        // TODO
        return;
    }

    u_short long_packet_type = (header_format & 0x3000) >> 4;
    switch (long_packet_type)
    {
    case 0x00:
        log_debug(" quic: initial");
        break;
    case 0x01:
        log_debug(" quic: 0-RTT");
        break;
    case 0x02:
        log_debug(" quic: handshake");
        break;
    case 0x03:
        log_debug(" quic: retry");
    default:
        break;
    }

    unsigned int quic_version = *(udp_payload + counter_pointer) << 24 |
        *(udp_payload + counter_pointer + 1) << 16 |
        *(udp_payload + counter_pointer + 2) << 8 |
        *(udp_payload + counter_pointer + 3);
    log_debug(" quic ver: %x", quic_version);
    counter_pointer += sizeof(quic_version);

    u_short dcil_scil = ntohs(*(udp_payload + counter_pointer)) >> 8;
    
    u_char dcil = (dcil_scil & 0xF0) >> 4;
    u_char scil = dcil_scil & 0x0F;
    
    dcil = dcil + (dcil == 0 ? 0 : 3);
    scil = scil + (scil == 0 ? 0 : 3);
    log_debug("dcil: %d, scil: %d", dcil, scil);
    counter_pointer++;
    u_char *destination_conn_id;
    counter_pointer += dcil;
    u_char *source_conn_id;
    counter_pointer += scil;

    if (long_packet_type == 0x00) {
        u_char *token_length_hdr = (u_char *)udp_payload + counter_pointer;
        counter_pointer++;
        uint64_t token_length = quic_decode_var_len_int(token_length_hdr);
        log_debug(" quic: token length: %d", token_length);

        // go through the token
        counter_pointer += token_length;
        u_char *length_hdr = (u_char *)udp_payload + counter_pointer;
        uint64_t length = quic_decode_var_len_int(length_hdr);
        log_debug(" quic: length: %d", length);
    }
}