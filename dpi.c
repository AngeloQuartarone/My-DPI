#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lib/hashMap.h"
#include "lib/dpi_utils.h"



int main(int argc, char *argv[])
{
    int option;

    if (argc < 2)
    {
        printf("Usage: %s -l (live capture) | -p <pcap file> (offline capture)\n", argv[0]);
        return 1;
    }

    while ((option = getopt(argc, argv, "lp:")) != -1)
    {
        switch (option)
        {
        case 'l':
        {
            char *dev;
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *handle;

            dev = pcap_lookupdev(errbuf);
            if (dev == NULL)
            {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return 1;
            }
            printf("Device found: %s\n", dev);

            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL)
            {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return 1;
            }

            pcap_loop(handle, 10, packet_handler_online, NULL);

            pcap_close(handle);
            break;
        }
        case 'p':
        {
            // packet_handler_offline(optarg);
            HashTable *table = hashCreate();
            process_packet(optarg, table);
            break;
        }
        default:
            printf("Usage: %s -l (live capture) | -p <pcap file> (offline capture)\n", argv[0]);
            return 1;
        }
    }

    return 0;
}

