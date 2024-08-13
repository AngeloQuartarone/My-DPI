#include "dpi.h"

enum sure
{
    weak,
    medium,
    strong
};

void packet_handler_online(u_char *, const struct pcap_pkthdr *, const u_char *);
void packet_handler_offline(const char *);
void print_payload(const unsigned char *, unsigned int);
void print_payload_as_string(const unsigned char *, unsigned int);
void process_packet(const char *, HashTable *);
char *create_str(const char[INET_ADDRSTRLEN], const char[INET_ADDRSTRLEN], unsigned int, unsigned int);
unsigned int flow_hash(const char *);

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

void packet_handler_online(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("IP src: %s -> IP dst: %s\n", src_ip, dst_ip);

    if (ip_header->ip_p == IPPROTO_TCP)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        printf("TCP src port: %d -> TCP dst port: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
    }
    else if (ip_header->ip_p == IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        printf("UDP src port: %d -> UDP dst port: %d\n", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
    }

    printf("\n");
}

void packet_handler_offline(const char *filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open file %s: %s\n", filename, errbuf);
        return;
    }

    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        ip_header = (struct ip *)(packet + 14);
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        printf("Packet length: %d bytes\n", header.len);
        printf("IP src: %s -> IP dst: %s\n", src_ip, dst_ip);

        switch (ip_header->ip_p)
        {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
            printf("Protocol: TCP\n");
            printf("Src port: %d -> Dst port: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
            break;
        case IPPROTO_UDP:
            udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
            printf("Protocol: UDP\n");
            printf("Src port: %d -> Dst port: %d\n", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            break;
        default:
            printf("Protocol: Other (%d)\n", ip_header->ip_p);
            break;
        }

        printf("\n");
    }

    pcap_close(handle);
}

void print_payload(const unsigned char *payload, unsigned int len)
{
    for (unsigned int i = 0; i < len; i++)
    {
        printf("%02x ", payload[i]); // Stampa i dati in formato esadecimale
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

void print_payload_as_string(const unsigned char *payload, unsigned int len)
{
    printf("Payload (string):\n");
    for (unsigned int i = 0; i < len; i++)
    {
        // Stampa solo i caratteri stampabili, altrimenti stampa un punto
        if (isprint(payload[i]))
        {
            printf("%c", payload[i]);
        }
        else
        {
            printf(".");
        }
    }
    printf("\n");
}

void print_flow(const flow_t *flow) {
    if (flow != NULL) {
        printf("Source IP: %s\n", flow->src_ip);
        printf("Destination IP: %s\n", flow->dst_ip);
        printf("Source Port: %u\n", flow->src_port);
        printf("Destination Port: %u\n", flow->dst_port);
        printf("Number of Packets: %u\n", flow->num_packet);
        printf("\n");
    }
}

// Funzione per stampare tutte le voci nella hash table
void print_hash_table(const HashTable *table) {
    for (int i = 0; i < SIZE; i++) {
        Item *current = table->items[i];
        while (current != NULL) {
            flow_t *flow = (flow_t *)current->value;
            printf("Key: %u\n", current->key);
            print_flow(flow);
            current = current->next;
        }
    }
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
        enum sure act_state;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        unsigned int src_port;
        unsigned int dst_port;
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        //printf("%s -> %s\n",src_ip, dst_ip);

        if (ip_header->ip_p == IPPROTO_TCP)
        {
            act_state = weak;
            tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
            src_port = ntohs(tcp_header->th_sport);
            dst_port = ntohs(tcp_header->th_dport);

            char *str1 = create_str(src_ip, dst_ip, src_port, dst_port);
            char *str2 = create_str(dst_ip, src_ip, dst_port, src_port);

            flow_t *f = (flow_t *)malloc(1 * sizeof(flow_t));
            strcpy(f->src_ip, src_ip);
            strcpy(f->dst_ip, dst_ip);
            f->src_port = src_port;
            f->dst_port = dst_port;
            f->num_packet = 1;


            // printf("%u, %u\n", flow_hash(str1), flow_hash(str2));

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
            //     act_state = medium;
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
            //             act_state = strong;
            //             printf("MQTT message type equals to 1 (CONNECT)\n");
            //             break;
            //         case 2:
            //             act_state = strong;
            //             printf("MQTT message type equals to 2 (CONNACK)\n");
            //             break;
            //         case 3:
            //             act_state = strong;
            //             printf("MQTT message type equals to 3 (PUBLISH)\n");
            //             break;
            //         case 8:
            //             act_state = strong;
            //             printf("MQTT message type equals to 8 (SUBSCRIBE)\n");
            //             break;
            //         case 14:
            //             act_state = strong;
            //             printf("MQTT message type equals to 14 (DISCONNECT)\n");
            //             break;
            //         default:
            //             printf("no MQTT message type\n");
            //             break;
            //         }

            // }
        }
    }
    print_hash_table(table);

    pcap_close(handle);
}

char *create_str(const char ip1[INET_ADDRSTRLEN], const char ip2[INET_ADDRSTRLEN], unsigned int port1, unsigned int port2)
{
    int length = strlen(ip1) + strlen(ip2) + 2 * 5 + 3; // 2 * 5 per le porte (massimo 5 caratteri per unsigned int) e 3 per i separatori ":" e "\0"

    char *result = (char *)malloc(length * sizeof(char));
    if (result == NULL)
    {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    snprintf(result, length, "%s:%u/%s:%u", ip1, port1, ip2, port2);

    return result;
}

unsigned int flow_hash(const char *str)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
    {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return (unsigned int)hash;
}