#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include "udp_handler.h"
#include "log.h"
 
void help()
{
    printf("usage:\n");
    printf("./how-quic -i interface -p server_port\n\n");
    printf("example:\n");
    printf("./how-quic -i lo -p 443\n");
}

int main(int argc, char *argv[])
{
    int c;
    char *device;
    char *server_ip;
    char *server_port;
    filter_server filter;
    
    opterr = 0;
    while ((c = getopt(argc, argv, "i:s:p:")) != -1)
        switch (c)
        {
        case 'i':
            device = optarg;
            break;
        case 'p':
            server_port = optarg;
            break;
        case '?':
            
            return 1;
        default:
            printf("hah\n");
            //return;
        }

    if (argc < 5) {
        help();
        return 1;
    }

    log_info("interface = %s, server port = %s\n",
           device, server_port);
    
    filter.server_port = (u_short)strtol(server_port, NULL, 10);

#if defined _DEBUG
    log_set_level(LOG_DEBUG);
#elif defined _TRACE
    log_set_level(LOG_TRACE);
#else
    log_set_level(LOG_INFO);
#endif

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;

    // end the loop after this many packets are captured
    int total_packet_count = 0; //40; // 0 for unlimited

    handle = pcap_open_live(device, snapshot_length, 0, 3000, error_buffer);
    if (handle == NULL)
    {
        log_fatal("could not open device %s: %s", device, error_buffer);
        return 2;
    }

    pcap_loop(handle, total_packet_count, udp_handler, (u_char*)&filter);
    return 0;
}
