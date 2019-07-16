#include <stdio.h>
#include <pcap.h>

#include "udp_handler.h"
#include "log.h"

int main(int argc, char *argv[])
{
    log_set_level(4);
    char *device = argc > 1 ? argv[1] : "lo";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;

    // end the loop after this many packets are captured
    int total_packet_count = 13;

    handle = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer);
    if (handle == NULL) {
        log_fatal("could not open device %s: %s", device, error_buffer);
        return 2;
    }
    
    pcap_loop(handle, total_packet_count, udp_handler, NULL);
    return 0;
}
