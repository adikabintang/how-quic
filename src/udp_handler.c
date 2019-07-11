#include "udp_handler.h"
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>

void udp_basic_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    struct ether_header *eth_hdr;
    eth_hdr = (struct ether_header *)packet;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
        printf("not an ip packet, skipping\n");
        return;
    }

    printf("total packet available: %d bytes\n", header->caplen);
    printf("expected packet size: %d bytes\n", header->len);

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    // header lengths in bytes
    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    // find the start of IP header
    ip_header = packet + ethernet_header_length;

    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("not a tcp packet, return\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = (*(tcp_header + 12) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;

    int total_headers_size = ethernet_header_length + ip_header_length
        + tcp_header_length;
    
    payload_length = header->caplen - (total_headers_size);

    payload = packet + total_headers_size;

    // print payload in ASCII
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
}

void udp_handler_v2(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    time_t local_tv_sec;
    struct tm ltime;
    char timestr[16];


    struct ether_header *eth_hdr;
    ip_header *ip_hdr;
    eth_hdr = (struct ether_header *)packet;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
        printf("not an ip packet, skipping\n");
        return;
    }

    // const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    // header lengths in bytes
    int ethernet_header_length = 14;
    int ip_header_length;

    // find the start of IP header
    ip_hdr = (ip_header *) (packet + ethernet_header_length);

    ip_header_length = (ip_hdr->ver_ihl & 0x0F) * 4;

    //u_char protocol = (ip_hdr + 9);
    if (ip_hdr->proto != IPPROTO_UDP) {
        printf("not a udp packet, return\n");
        return;
    }

    udp_header *udp_hdr = (udp_header *)
        ((u_char *)ip_hdr + ip_header_length);
    
    u_short src_port = ntohs(udp_hdr->src_port);
    u_short dst_port = ntohs(udp_hdr->dst_port);

    printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
        ip_hdr->saddr.byte1,
        ip_hdr->saddr.byte2,
        ip_hdr->saddr.byte3,
        ip_hdr->saddr.byte4,
        src_port,
        ip_hdr->daddr.byte1,
        ip_hdr->daddr.byte2,
        ip_hdr->daddr.byte3,
        ip_hdr->daddr.byte4,
        dst_port);

    int payload_length;

    local_tv_sec = header->ts.tv_sec;
    printf("%lld.%.9ld\n", (long long)header->ts.tv_sec, header->ts.tv_usec);

    /* print timestamp and length of the packet */
    printf("total packet available: %d bytes\n", header->caplen);
    printf("expected packet size: %d bytes\n", header->len);
    u_short datagram_length = ntohs(udp_hdr->len);
    printf("real_length: %d\n", datagram_length);
}