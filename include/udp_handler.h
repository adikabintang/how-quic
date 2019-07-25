#ifndef UDP_HANDLER_H_
#define UDP_HANDLER_H_

#include <pcap.h>

/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

typedef struct filter_server {
    u_short server_port;
} filter_server;

/* IPv4 header */
typedef struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
} ip_header;

/* UDP header: https://en.wikipedia.org/wiki/User_Datagram_Protocol*/
typedef struct udp_header {
    // Source port
    u_short src_port;
    // Destination port
    u_short dst_port; 
    // Datagram length: udp header (fixed 8 bytes) + udp payload length
    u_short len;
    // Checksum
    u_short crc;
} udp_header;

void udp_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);

#endif