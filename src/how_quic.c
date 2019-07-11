#include <stdio.h>
#include <pcap.h>

#include "udp_handler.h"

int main(int argc, char *argv[])
{
    char *device = argc > 1 ? argv[1] : "lo";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;

    // end the loop after this many packets are captured
    int total_packet_count = 5;

    handle = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "could not open device %s: %s\n", device, error_buffer);
        return 2;
    }
    
    pcap_loop(handle, total_packet_count, udp_handler_v2, NULL);
    return 0;
}