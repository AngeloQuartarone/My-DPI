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
#include "hashMap.h"
#include "dpi_utils.h"

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

void print_flow(const flow_t *flow)
{
    if (flow != NULL)
    {
        printf("Source IP: %s\n", flow->src_ip);
        printf("Destination IP: %s\n", flow->dst_ip);
        printf("Source Port: %u\n", flow->src_port);
        printf("Destination Port: %u\n", flow->dst_port);
        printf("Number of Packets: %u\n", flow->num_packet);
        printf("\n");
    }
}

// Funzione per stampare tutte le voci nella hash table
void print_hash_table(const HashTable *table)
{
    for (int i = 0; i < SIZE; i++)
    {
        Item *current = table->items[i];
        while (current != NULL)
        {
            flow_t *flow = (flow_t *)current->value;
            printf("Key: %u\n", current->key);
            print_flow(flow);
            current = current->next;
        }
    }
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
