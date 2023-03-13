#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include "udp_handler.h"
#include "log.h"
 
void help()
{
    printf("usage:\n");
    printf("   ./how-quic -i interface -p server_port\n");
    printf("or ./how-quic -t trace-file.pcap -p server_port\n");
    printf("example:\n");
    printf("   ./how-quic -i lo -p 443\n");
}

int main(int argc, char *argv[])
{
    int c;
    char *device = NULL;
    char *trace_path = NULL;
    char *server_ip;
    char *server_port = NULL;
    filter_server filter;
    
    opterr = 0;
    while ((c = getopt(argc, argv, "t:i:s:p:")) != -1)
        switch (c)
        {
        case 'i':
            device = optarg;
            break;
        case 'p':
            server_port = optarg;
            break;
        case 't':
            trace_path = optarg;
            break;
        case '?':
            return 1;
        default:
            printf("hah\n");
            //return;
        }

    if ( (device == NULL && trace_path == NULL) || server_port == NULL ){
        help();
        return 1;
    }

#if defined _DEBUG
    log_set_level(LOG_DEBUG);
#elif defined _TRACE
    log_set_level(LOG_TRACE);
#else
    log_set_level(LOG_INFO);
#endif
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // end the loop after this many packets are captured
    int total_packet_count = 0; //40; // 0 for unlimited

    // analyze only packets coming from/to this port
    log_info("port filter = %s\n", server_port );
    filter.server_port = (u_short)strtol(server_port, NULL, 10);

    //online analysis packets from network interface card
    if( device != NULL ){
        log_info("interface = %s\n", device);
        int snapshot_length = 1024;
        handle = pcap_open_live(device, snapshot_length, 0, 3000, error_buffer);
        if (handle == NULL)
        {
            log_fatal("could not open device %s: %s", device, error_buffer);
            return 2;
        }
    }
    //offline analysis packets from a .pcap file
    else if( trace_path != NULL ){
        log_info("trace file = %s\n", trace_path );
        handle = pcap_open_offline( trace_path, error_buffer );
        if( handle == NULL ){
            log_fatal("could not open file %s: %s", trace_path, error_buffer);
            return 2;
        }
    } else {
        log_fatal("need to provide either -i or -t parameter");
    }
    pcap_loop(handle, total_packet_count, udp_handler, (u_char*)&filter);
    return 0;
}
