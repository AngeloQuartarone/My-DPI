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

typedef struct
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned int src_port;
    unsigned int dst_port;
    unsigned int num_packet;
} flow_t;


