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

void process_packet(const char *filename, HashTable *table);

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
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_if_t *alldevs;
            pcap_if_t *dev;
            pcap_t *handle;

            if (pcap_findalldevs(&alldevs, errbuf) == -1)
            {
                fprintf(stderr, "Couldn't find devices: %s\n", errbuf);
                return 1;
            }

            if (alldevs == NULL)
            {
                fprintf(stderr, "No devices found\n");
                return 1;
            }

            dev = alldevs; // Use the first available device
            printf("Device found: %s\n", dev->name);

            handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL)
            {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
                pcap_freealldevs(alldevs);
                return 1;
            }

            pcap_loop(handle, 10, packet_handler_online, NULL);

            pcap_close(handle);
            pcap_freealldevs(alldevs);
            break;
        }
        case 'p':
        {
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

void process_packet(const char *filename, HashTable *table)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ip *ip_header;
    struct tcphdr *tcp_header;

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
        return;
    }

    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        ip_header = (struct ip *)(packet + 14); // Header IP
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        unsigned int src_port;
        unsigned int dst_port;
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        char *str1 = NULL;
        char *str2 = NULL;

        if (ip_header->ip_p == IPPROTO_TCP)
        {
            tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
            src_port = ntohs(tcp_header->th_sport);
            dst_port = ntohs(tcp_header->th_dport);

            str1 = create_str(src_ip, dst_ip, src_port, dst_port);
            str2 = create_str(dst_ip, src_ip, dst_port, src_port);

            flow_t *f = (flow_t *)malloc(1 * sizeof(flow_t));
            strcpy(f->src_ip, src_ip);
            strcpy(f->dst_ip, dst_ip);
            f->src_port = src_port;
            f->dst_port = dst_port;
            f->num_packet = 1;

            if ((hashSearch(table, flow_hash(str1)) != NULL) || (hashSearch(table, flow_hash(str2)) != NULL))
            {
                // hashInsert(table, flow_hash(str1), f);
                flow_t *actual_flow = (flow_t *)hashSearch(table, flow_hash(str1));
                if (actual_flow == NULL)
                {
                    actual_flow = (flow_t *)hashSearch(table, flow_hash(str2));
                }
                actual_flow->num_packet++;
            }
            else
            {
                hashInsert(table, flow_hash(str1), f);
            }

            // if (src_port == 1883 || dst_port == 1883)
            // {
            // }

            // unsigned int ip_header_len = ip_header->ip_hl * 4;
            // unsigned int tcp_header_len = tcp_header->th_off * 4;
            // unsigned int payload_offset = 14 + ip_header_len + tcp_header_len;
            // unsigned char *payload = (unsigned char *)(packet + payload_offset);

            // unsigned int total_len = ntohs(ip_header->ip_len);
            // unsigned int payload_len = total_len - (ip_header_len + tcp_header_len);

            // if (payload_len > 0)
            // {
            //     unsigned char mqtt_message_type = (payload[0] >> 4) & 0x0F;

            //         switch (mqtt_message_type)
            //         {
            //         case 1:
            //             printf("MQTT message type equals to 1 (CONNECT)\n");
            //             break;
            //         case 2:
            //             printf("MQTT message type equals to 2 (CONNACK)\n");
            //             break;
            //         case 3:
            //             printf("MQTT message type equals to 3 (PUBLISH)\n");
            //             break;
            //         case 8:
            //             printf("MQTT message type equals to 8 (SUBSCRIBE)\n");
            //             break;
            //         case 14:
            //             printf("MQTT message type equals to 14 (DISCONNECT)\n");
            //             break;
            //         default:
            //             printf("no MQTT message type\n");
            //             break;
            //         }

            // }
        }
        free(str1);
        free(str2);
    }
    print_hash_table(table);

    pcap_close(handle);
}
