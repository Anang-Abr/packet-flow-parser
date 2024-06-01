#ifndef HANDLER_H
#define HANDLER_H
#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include "../flow.h"

void tcp_handler(FlowsBuffer *fb, const unsigned char *packet, const struct pcap_pkthdr *pkthdr);

FlowInfo *find_flow_index(
    FlowsBuffer *flowBuffer,
    const struct in_addr src_ip,
    const struct in_addr dst_ip,
    const uint16_t src_port,
    const uint16_t dst_port);

void tcp_update_flow(
    FlowInfo *flow,
    const unsigned char *packet,
    const struct pcap_pkthdr *pkthdr);

FlowInfo *tcp_generate_new_flow(
    const unsigned char *packet,
    const struct pcap_pkthdr *pkthdr);

void reuse_flow(
    FlowInfo *rf,
    const unsigned char *packet,
    const struct pcap_pkthdr *pkthdr);
                     
#endif