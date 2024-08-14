typedef struct
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned int src_port;
    unsigned int dst_port;
    unsigned int num_packet;
} flow_t;

void packet_handler_online(u_char *, const struct pcap_pkthdr *, const u_char *);
void packet_handler_offline(const char *);
void print_payload(const unsigned char *, unsigned int);
void print_payload_as_string(const unsigned char *, unsigned int);
void process_packet(const char *, HashTable *);
char *create_str(const char[INET_ADDRSTRLEN], const char[INET_ADDRSTRLEN], unsigned int, unsigned int);
unsigned int flow_hash(const char *);


