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

void quic_parse_header(const u_char *udp_payload, unsigned int payload_length)
{
    unsigned int counter_pointer = 0;
    unsigned int i;
    decode_var_len_data var_len;

    while (counter_pointer < payload_length)
    {
        log_warn("cp: %ld, pl: %ld", counter_pointer, payload_length);
        u_char header_format = *(udp_payload + counter_pointer);
        counter_pointer++;

        log_debug(" quic header format: %x", header_format);
        u_char x = header_format & 0x80;

        if (x == 0x80)
        {
            log_debug(" quic: long header");
        }
        else
        {
            log_error(" quic: short header");
            u_char spin_bit = (header_format & 0x20) >> 5;
            log_error(" spinbit: %d", spin_bit);
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

            log_error("timstamp %lld ms", timestamp_msec);
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
                    log_error("rtt: %lld ms", rtt_ms);
                    log_error("rtt: %lld us", rtt_us);
                }
                else
                {
                    log_error("same spinbit");
                }
            }
            log_error("---\n");
            // TODO
            return;
        }

        u_char long_packet_type = (header_format & 0x30) >> 4;
        switch (long_packet_type)
        {
        case QUIC_INITIAL_PACKET:
            log_debug(" quic type: initial");
            break;
        case QUIC_ZERO_RTT_PACKET:
            log_debug(" quic type: 0-RTT");
            break;
        case QUIC_HANDSHAKE_PACKET:
            log_debug(" quic type: handshake");
            break;
        case QUIC_RETRY_PACKET:
            log_debug(" quic type: retry");
        default:
            return;
        }

        uint32_t quic_version = *(udp_payload + counter_pointer) << 24 |
                                *(udp_payload + counter_pointer + 1) << 16 |
                                *(udp_payload + counter_pointer + 2) << 8 |
                                *(udp_payload + counter_pointer + 3);
        log_debug(" quic ver: %x", quic_version);
        counter_pointer += sizeof(uint32_t);

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

        if (long_packet_type == QUIC_INITIAL_PACKET)
        {
            u_char *token_length_hdr = (u_char *)udp_payload + counter_pointer;
            counter_pointer++;
            // (usable bit - 6)/8
            var_len = quic_decode_var_len_int(token_length_hdr);

            log_debug(" quic: token length: %d", var_len.value);
            counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

            // go through the token
            counter_pointer += var_len.value;

            u_char *length_hdr = (u_char *)udp_payload + counter_pointer;
            counter_pointer++;

            var_len = quic_decode_var_len_int(length_hdr);
            counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

            log_debug(" quic: length: %d", var_len.value);
            counter_pointer += var_len.value;
        }
        else if (long_packet_type == QUIC_ZERO_RTT_PACKET ||
                 long_packet_type == QUIC_HANDSHAKE_PACKET)
        {
            u_char *length_hdr = (u_char *)udp_payload + counter_pointer;
            counter_pointer++;

            var_len = quic_decode_var_len_int(length_hdr);
            log_debug(" quic: length: %d", var_len.value);
            counter_pointer += ((var_len.excessive_usable_bit - 6) / 8);

            counter_pointer += var_len.value;
        }
        else if (long_packet_type == QUIC_RETRY_PACKET)
        {
            log_error("retry");
            // TODO
            return;
            // u_char *length_hdr = (u_char *)udp_payload + counter_pointer;
            // uint64_t length = quic_decode_var_len_int(length_hdr);
            // log_debug(" quic: length: %d", length);
            // counter_pointer += length;
        }
    }

    log_debug("---\n");
}
