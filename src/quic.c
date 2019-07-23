#include "quic.h"
#include "log.h"
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>      /* time_t, time (for timestamp in second) */
#include <sys/timeb.h> /* ftime, timeb (for timestamp in millisecond) */
#include <sys/time.h>   // gettimeofday, timeval (for timestamp in microsecond)

#define QUIC_INITIAL_PACKET 0x0
#define QUIC_ZERO_RTT_PACKET 0x1
#define QUIC_HANDSHAKE_PACKET 0x2
#define QUIC_RETRY_PACKET 0x3
#define QUIC_LONG_HEADER_FORMAT 0x80

u_char g_spinbit = 0xff;
long long int g_timestamp_msec;
long long int g_timestamp_usec;

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

void handle_initial_packet(const u_char *udp_payload, 
    unsigned int payload_length, unsigned int *counter_pointer)
{   
    u_char *token_length_hdr = (u_char *)udp_payload + *counter_pointer;
    (*counter_pointer)++;
    decode_var_len_data var_len = quic_decode_var_len_int(token_length_hdr);

    *counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

    // go through the token
    *counter_pointer += var_len.value;

    u_char *length_hdr = (u_char *)udp_payload + *counter_pointer;
    (*counter_pointer)++;

    var_len = quic_decode_var_len_int(length_hdr);
    *counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

    *counter_pointer += var_len.value;
}

void handle_0_rtt_or_handhsake(const u_char *udp_payload, 
    unsigned int payload_length, unsigned int *counter_pointer)
{
    decode_var_len_data var_len;
    u_char *length_hdr = (u_char *)udp_payload + *counter_pointer;
    (*counter_pointer)++;

    var_len = quic_decode_var_len_int(length_hdr);
    *counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

    *counter_pointer += var_len.value;
}

void measure_latency_spinbit(u_char header_format)
{
    log_debug("quic SHORT header");
    u_char spin_bit = (header_format & 0x20) >> 5;
    log_debug(" spinbit: %d", spin_bit);
    struct timeb timer_msec;
    long long int timestamp_msec; /* timestamp in millisecond. */
    if (!ftime(&timer_msec))
    {
        timestamp_msec = ((long long int)timer_msec.time) * 1000ll +
            (long long int)timer_msec.millitm;
    }
    else
    {
        timestamp_msec = -1;
    }

    /* Example of timestamp in microsecond. */
    struct timeval timer_usec; 
    long long int timestamp_usec; /* timestamp in microsecond */
    if (!gettimeofday(&timer_usec, NULL)) {
        timestamp_usec = ((long long int) timer_usec.tv_sec) * 
            1000000ll + (long long int) timer_usec.tv_usec;
    }
    else {
        timestamp_usec = -1;
    }

    log_debug("timstamp %lld ms", timestamp_msec);
    if (g_spinbit == 0xff)
    {
        g_spinbit = spin_bit;
        g_timestamp_msec = timestamp_msec;
        g_timestamp_usec = timestamp_usec;
    }
    else
    {
        if (g_spinbit != spin_bit)
        {
            g_spinbit = spin_bit;
            long long int rtt_ms = timestamp_msec - g_timestamp_msec;
            long long int rtt_us = timestamp_usec - g_timestamp_usec;
            g_timestamp_msec = timestamp_msec;
            g_timestamp_usec = timestamp_usec;
            log_info("rtt: %lld ms", rtt_ms);
            log_info("rtt: %lld us", rtt_us);
        }
        else
        {
            log_debug("same spinbit");
        }
    }
    log_info("---\n");
    // TODO
    return;
}

void quic_parse_header(const u_char *udp_payload, unsigned int payload_length)
{
    unsigned int counter_pointer = 0;
    unsigned int i;
    u_char long_or_short_header;

    while (counter_pointer < payload_length) {
        u_char header_format = *(udp_payload + counter_pointer);
        counter_pointer++;
        
        long_or_short_header = header_format & 0x80;

        if (long_or_short_header == QUIC_LONG_HEADER_FORMAT) {
            u_char long_packet_type = (header_format & 0x30) >> 4;

            // TODO: this looks worrying because of the endianness problem
            uint32_t quic_version = *(udp_payload + counter_pointer) << 24 |
                                    *(udp_payload + counter_pointer + 1) << 16 |
                                    *(udp_payload + counter_pointer + 2) << 8 |
                                    *(udp_payload + counter_pointer + 3);

            log_debug(" quic ver: %x", quic_version);
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
                log_debug(" quic type: initial");
                handle_initial_packet(udp_payload, payload_length, 
                    &counter_pointer);
                break;
            case QUIC_ZERO_RTT_PACKET:
                log_debug(" quic type: 0-RTT");
                handle_0_rtt_or_handhsake(udp_payload, payload_length, 
                    &counter_pointer);
                break;
            case QUIC_HANDSHAKE_PACKET:
                log_debug(" quic type: handshake");
                handle_0_rtt_or_handhsake(udp_payload, payload_length, 
                    &counter_pointer);
                break;
            case QUIC_RETRY_PACKET:
                log_debug(" quic type: retry");
                return;
            default:
                return;
            }
        } 
        else
        {
            measure_latency_spinbit(header_format);
            return;
        }
    }
}

