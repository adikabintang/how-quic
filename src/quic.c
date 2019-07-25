#include "quic.h"
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <sys/timeb.h>
#include <sys/time.h>
#include "log.h"
#include "uthash.h"
#include "util.h"

#define QUIC_INITIAL_PACKET 0x0
#define QUIC_ZERO_RTT_PACKET 0x1
#define QUIC_HANDSHAKE_PACKET 0x2
#define QUIC_RETRY_PACKET 0x3
#define QUIC_LONG_HEADER_FORMAT 0x80

typedef struct quic_conversation
{
    char key_src_dst_ip_port[43]; /* key format: ip:portip:port, not srcdestination */
    u_char last_spinbit;
    long long last_timestamp_ms;
    long long last_timestamp_us;
    long long rtt_ms;
    long long rtt_us;
    UT_hash_handle hh; /* makes this structure hashable */
} conversation;

conversation *g_conv = NULL;

void quic_measure_latency_spinbit(char *src_ip_port, char *dst_ip_port,
                                  u_char spinbit)
{
    conversation *temp_conv;
    char key[43] = "";
    if (strcmp(src_ip_port, dst_ip_port) < 0)
    {
        strcpy(key, src_ip_port);
        strcat(key, dst_ip_port);
    }
    else
    {
        strcpy(key, dst_ip_port);
        strcat(key, src_ip_port);
    }

    log_trace("key: %s", key);
    log_trace(" spinbit: %d", spinbit);
    HASH_FIND_STR(g_conv, key, temp_conv);
    if (temp_conv)
    {
        log_debug("conversation already exists");
        if (temp_conv->last_spinbit != spinbit)
        {
            long long current_ms = get_current_msec();
            temp_conv->rtt_ms = current_ms - temp_conv->last_timestamp_ms;
            temp_conv->last_timestamp_ms = current_ms;
            log_trace("spinning!");
            //temp_conv->rtt_us = current_us - temp_conv->last_timestamp_us;
            
            //temp_conv->last_timestamp_us = current_us;
            // temp_conv->rtt_ms = temp_conv->rtt_us / 1000;
            // temp_conv->last_timestamp_ms = current_us / 1000;
            temp_conv->last_spinbit = spinbit;
            log_info("%s <-> %s", src_ip_port, dst_ip_port);
            log_info("rtt: %lld us", temp_conv->rtt_us);
            log_info("rtt: %lld ms", temp_conv->rtt_ms);
            log_info("---\n");
        }
        else
        {
            log_trace("same spin bit");
        }
    }
    else
    {
        log_trace("conversation does NOT exist, creating a new one...");
        temp_conv = (conversation *)malloc(sizeof(conversation));
        strcpy(temp_conv->key_src_dst_ip_port, key);
        temp_conv->last_spinbit = spinbit;
        //temp_conv->last_timestamp_us = get_current_usec();
        temp_conv->last_timestamp_ms = get_current_msec();
        temp_conv->rtt_ms = 0;
        temp_conv->rtt_us = 0;
        HASH_ADD_STR(g_conv, key_src_dst_ip_port, temp_conv);
    }
}

/**
 * https://tools.ietf.org/html/draft-ietf-quic-transport-22#section-16
 */
decode_var_len_data quic_decode_var_len_int(u_char *header_field)
{
    uint8_t var_len = 0;
    uint64_t value = 0;
    uint8_t usable_bit = 0;
    decode_var_len_data result;

    var_len = (*header_field & 0b11000000) >> 6;
    switch (var_len)
    {
    case 0b00:
        usable_bit = 6;
        result.excessive_usable_bit = 6;
        break;
    case 0b01:
        usable_bit = 14;
        result.excessive_usable_bit = 14;
        break;
    case 0b10:
        usable_bit = 30;
        result.excessive_usable_bit = 30;
        break;
    case 0b11:
        usable_bit = 62;
        result.excessive_usable_bit = 62;
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
    result.value = value;
    return result;
}

void quic_handle_initial_packet(const u_char *udp_payload,
                                unsigned int payload_length,
                                unsigned int *counter_pointer)
{
    u_char *token_length_hdr = (u_char *)udp_payload + *counter_pointer;
    (*counter_pointer)++;
    decode_var_len_data var_len = quic_decode_var_len_int(token_length_hdr);

    *counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

    // skip the token
    *counter_pointer += var_len.value;

    u_char *length_hdr = (u_char *)udp_payload + *counter_pointer;
    (*counter_pointer)++;

    var_len = quic_decode_var_len_int(length_hdr);
    *counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

    *counter_pointer += var_len.value;
}

void quic_handle_0_rtt_or_handhsake(const u_char *udp_payload,
                                    unsigned int payload_length,
                                    unsigned int *counter_pointer)
{
    decode_var_len_data var_len;
    u_char *length_hdr = (u_char *)udp_payload + *counter_pointer;
    (*counter_pointer)++;

    var_len = quic_decode_var_len_int(length_hdr);
    *counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

    *counter_pointer += var_len.value;
}

void quic_parse_header(const u_char *udp_payload, unsigned int payload_length,
                       char *src_ip_port, char *dst_ip_port)
{
    unsigned int counter_pointer = 0;
    unsigned int i;
    u_char long_or_short_header;

    while (counter_pointer < payload_length)
    {
        u_char header_format = *(udp_payload + counter_pointer);
        counter_pointer++;

        long_or_short_header = header_format & 0x80;

        if (long_or_short_header == QUIC_LONG_HEADER_FORMAT)
        {
            u_char long_packet_type = (header_format & 0x30) >> 4;

            // TODO: this looks worrying because of the endianness problem
            // but only affects the quic version printing,
            // not the rtt measurement
            uint32_t quic_version = *(udp_payload + counter_pointer) << 24 |
                                    *(udp_payload + counter_pointer + 1) << 16 |
                                    *(udp_payload + counter_pointer + 2) << 8 |
                                    *(udp_payload + counter_pointer + 3);

            log_trace(" quic ver: %x", quic_version);
            counter_pointer += sizeof(uint32_t);

            u_char dcid_len = *(udp_payload + counter_pointer);
            counter_pointer++;

            // skipping dcid
            counter_pointer += dcid_len;

            u_char scid_len = *(udp_payload + counter_pointer);
            counter_pointer++;

            // skipping scid
            counter_pointer += scid_len;

            switch (long_packet_type)
            {
            case QUIC_INITIAL_PACKET:
                log_trace(" quic type: initial");
                quic_handle_initial_packet(udp_payload, payload_length,
                                           &counter_pointer);
                break;
            case QUIC_ZERO_RTT_PACKET:
            case QUIC_HANDSHAKE_PACKET:
                log_trace(" quic type: handshake or 0-RTT");
                quic_handle_0_rtt_or_handhsake(udp_payload, payload_length,
                                               &counter_pointer);
                break;
            case QUIC_RETRY_PACKET:
                log_trace(" quic type: retry");
                return;
            default:
                return;
            }
        }
        else
        {
            u_char spinbit = (header_format & 0x20) >> 5;
            quic_measure_latency_spinbit(src_ip_port, dst_ip_port, spinbit);
            return;
        }
    }
}
