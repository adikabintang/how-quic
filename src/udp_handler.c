#include "udp_handler.h"
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include "log.h"
#include "quic.h"

uint32_t counter = 1;

void udp_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    time_t local_tv_sec;
    struct tm ltime;
    char timestr[16];

    filter_server *filter = (filter_server *)args;
    
    struct ether_header *eth_hdr;
    ip_header *ip_hdr;
    eth_hdr = (struct ether_header *)packet;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
        log_trace("not an ip packet, skipping");
        return;
    }

    // header lengths in bytes
    int ethernet_header_length = 14;
    int ip_header_length;

    // find the start of IP header
    ip_hdr = (ip_header *) (packet + ethernet_header_length);

    ip_header_length = (ip_hdr->ver_ihl & 0x0F) * 4;

    //u_char protocol = (ip_hdr + 9);
    if (ip_hdr->proto != IPPROTO_UDP) {
        log_trace("not a udp packet, return");
        return;
    }

    udp_header *udp_hdr = (udp_header *)
        ((u_char *)ip_hdr + ip_header_length);
    
    u_short src_port = ntohs(udp_hdr->src_port);
    u_short dst_port = ntohs(udp_hdr->dst_port);
    u_short datagram_length = ntohs(udp_hdr->len);
    
    if (dst_port == filter->server_port || src_port == filter->server_port)
    {
        local_tv_sec = header->ts.tv_sec;

        /* print timestamp and length of the packet */
        log_trace("total packet available: %d bytes", header->caplen);
        log_trace("expected packet size: %d bytes", header->len);
        
        log_trace("real_length: %d bytes", datagram_length);
        log_trace("udp payload_length: %d bytes", datagram_length - 8);
        log_debug("\n\n---\nPACKET: %d\n---", counter++);
        char src_ip_port[22]; // format: xxx.xxx.xxx.xxx:xxxxx
        char dst_ip_port[22];
        snprintf(src_ip_port, 22, "%d.%d.%d.%d:%d", 
            ip_hdr->saddr.byte1,
            ip_hdr->saddr.byte2,
            ip_hdr->saddr.byte3,
            ip_hdr->saddr.byte4,
            src_port);
        
        snprintf(dst_ip_port, 22, "%d.%d.%d.%d:%d", 
            ip_hdr->daddr.byte1,
            ip_hdr->daddr.byte2,
            ip_hdr->daddr.byte3,
            ip_hdr->daddr.byte4,
            dst_port);

        log_debug("%lld.%.6ld", (long long)header->ts.tv_sec, 
            header->ts.tv_usec);
        quic_parse_header(header, packet + ethernet_header_length 
            + ip_header_length + 8, datagram_length - 8, src_ip_port, 
            dst_ip_port);
    }
}