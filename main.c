#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "utils/cJSON.h"
#include "utils/cJSON.c"
#include <time.h>
#include <assert.h>
#include "flow.h"
#include "./handler/handler.h"


#define MAX_FLOWS 10
#define MAX_PACKETS 30


FlowInfo flows[MAX_FLOWS];
unsigned int flow_count = 0;
unsigned int packet_count = 0;
char protocol = 'O';
unsigned int tcp_flow = 0;
unsigned int udp_flow = 0;
pcap_dumper_t *pcap_dumper;
FlowsBuffer *flowBuffer;

void process_packet(const unsigned char *packet, int payload_offset, int payload_length)
{
    printf("Payload: ");
    for (int i = payload_offset; i < payload_offset + payload_length; ++i)
    {
        printf("%02x ", packet[i]);
    }
    printf("\n");
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    //PROTOCOL TCP
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    if (ip_header->ip_p == IPPROTO_TCP)
    {
        tcp_handler((FlowsBuffer*)user_data, packet, pkthdr);
    }
    
}

/**
 * TODO
 * ? Install zeek flowmeter
*/

void initFlowBuffer(FlowsBuffer* fbs, unsigned int initSize){
    fbs->flows = (FlowInfo*)malloc(sizeof(FlowInfo)*initSize);
    fbs->capacity = initSize;
    fbs->count = 0;
}

int main(int argc, char **argv)
{
    pcap_t *handle;
    flowBuffer = (FlowsBuffer *)malloc(sizeof(FlowsBuffer));
    initFlowBuffer(flowBuffer, 2);
    char errbuf[PCAP_ERRBUF_SIZE];
    cJSON *flowArr = cJSON_CreateArray();
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }
    pcap_loop(handle, 0, packet_handler, (unsigned char *)flowBuffer);
    pcap_close(handle);
    printf("Total UDP Flowss: %d\n", udp_flow);
    printf("Total TCP Flows: %d\n", tcp_flow);
    fclose;
    return 0;
}