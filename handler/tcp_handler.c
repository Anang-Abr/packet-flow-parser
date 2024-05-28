#ifndef TCP_HANDLER
#define TCP_HANDLER
#include <netinet/ether.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "handler.h"
#include "../flow.h"
#include <stdio.h>
#include <time.h>

int ARR_SIZE = 100;

int count = 0;

void printFlowInfo(FlowInfo *f){
    FILE *fptr;
    struct tm ts;
    struct tm te;
    char start[80];
    char end[80];
    time_t time_start = f->ts_sec[0];
    time_t time_end = f->ts_sec[f->packet_count-1];
    gmtime_r(&time_start, &ts);
    gmtime_r(&time_end, &te);
    strftime(start, sizeof(start), "%Y-%m-%d %H:%M:%S", &ts);
    strftime(end, sizeof(end), "%Y-%m-%d %H:%M:%S", &te);

    fptr = fopen("./captured_packets/flow.log", "a");
    if(fptr == NULL){
        perror("failed to open the log");
    }
    if (
        fprintf(fptr, "%-3d|%s.%06ld - %s.%06ld|[%-12s:%-5d -> %-12s:%-5d]==>%-6d\n",
        ++count, start, f->ts_msec[0],  end,  f->ts_msec[f->packet_count - 1], inet_ntoa(f->src_ip), f->src_port, inet_ntoa(f->dst_ip), f->dst_port, f->packet_count) < 0)
    {
        perror("error writing to file");
    }
    printf("===\n");
    // printf("Source IP   : %s\n",inet_ntoa(f->src_ip));
    // printf("Dest IP     : %s\n", inet_ntoa(f->dst_ip));
    // printf("Source Port : %d\n", f->src_port);
    // printf("Source Port : %d\n", f->dst_port);
    // printf("Forward pkt : %d\n", f->fwd);
    // printf("Backward pkt: %d\n", f->bwd);
    // printf("Protocol    : %d\n", f->protocol);
    // printf("ms          : ");
    for(int i = 0; i< f->packet_count; i++){
        if(i%5 == 0){
            printf("\n");
        }
        printf("%ld, ", f->ts_msec[i]);
    }
    // printf("]\n");
    if (fclose(fptr) != 0)
    {
        perror("failed to close the log");
    }
}

    bool check_flag(uint8_t flag, uint8_t compare)
{
    return ((flag & compare) > 0);
}

FlowInfo *find_flow_index(
    FlowsBuffer *flowBuffer,
    const struct in_addr src_ip,
    const struct in_addr dst_ip,
    const uint16_t src_port,
    const uint16_t dst_port)
{
    for (int i = 0; i < flowBuffer->count; i++)
    {
        if ((
                flowBuffer->flows[i].src_ip.s_addr == src_ip.s_addr &&
                flowBuffer->flows[i].dst_ip.s_addr == dst_ip.s_addr &&
                flowBuffer->flows[i].src_port == src_port &&
                flowBuffer->flows[i].dst_port == dst_port) ||
            (flowBuffer->flows[i].src_ip.s_addr == dst_ip.s_addr &&
             flowBuffer->flows[i].dst_ip.s_addr == src_ip.s_addr &&
             flowBuffer->flows[i].src_port == dst_port &&
             flowBuffer->flows[i].dst_port == src_port))
        {
            return &flowBuffer->flows[i];
        }
    }
    return NULL;
}


void tcp_handler(FlowsBuffer *fb, const unsigned char *packet, const struct pcap_pkthdr *pkthdr)
{
    if(fb->count >= fb->capacity){
        fb->capacity *= 2;
        printf("reallocating to %ld bytes\n", fb->capacity*sizeof(FlowInfo));
        fb->flows = realloc(fb->flows, sizeof(FlowInfo)*fb->capacity);
    }
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    const struct ethhdr *eth_header = (struct ethhdr *)packet;
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
    FlowInfo *found_flow = find_flow_index(fb, ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
    int flow_packet_count;
    bool is_fwd;
    if (found_flow == NULL)
    {
        found_flow = tcp_generate_new_flow(packet, pkthdr);
        fb->flows[fb->count] = *found_flow;
    }
    // when the same flow is found, update flow information
    else
    {
        tcp_update_flow(found_flow, packet, pkthdr);
    }
    fb->count++;
}

FlowInfo *tcp_generate_new_flow(
    const unsigned char *packet,
    const struct pcap_pkthdr *pkthdr)
{
    // printf("buat flow baru\n");
    FlowInfo* new_flow = (FlowInfo*)malloc(sizeof(FlowInfo));
    const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ethhdr));
    const struct ethhdr *eth_hdr = (struct ethhdr *)packet;
    const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_hdr->ip_hl * 4);
    int tcp_hdr_size = tcp_hdr->th_off * 4;
    int ip_hdr_size = ip_hdr->ip_hl * 4;
    int payload_size = ip_hdr->ip_len - ip_hdr_size - tcp_hdr_size;
    new_flow->src_ip = ip_hdr->ip_src;
    new_flow->dst_ip = ip_hdr->ip_dst;
    new_flow->src_port = ntohs(tcp_hdr->th_sport);
    new_flow->dst_port = ntohs(tcp_hdr->th_dport);
    new_flow->protocol = 'T';
    new_flow->packet_count = 0;
    new_flow->fwd = 0;
    new_flow->bwd = 0;
    new_flow->fwd_tot = tcp_hdr->th_off * 4;
    new_flow->bwd_tot = 0;
    new_flow->fwd_hdr_min = 0;
    new_flow->bwd_hdr_min = 0;
    new_flow->fwd_hdr_max = 0;
    new_flow->bwd_hdr_max = 0;
    new_flow->fwd_pkts_payload_min = 0;
    new_flow->FIN_count = 0;
    new_flow->SYN_count = 0;
    new_flow->PSH_fwd_count = 0;
    new_flow->PSH_bwd_count = 0;
    new_flow->ACK_count = 0;
    new_flow->URG_fwd_count = 0;
    new_flow->URG_bwd_count = 0;
    new_flow->ECE_count = 0;
    new_flow->CWR_count = 0;
    new_flow->RST_count = 0;
    new_flow->ts_sec = malloc(sizeof(long) * ARR_SIZE);
    new_flow->ts_msec = malloc(sizeof(long) * ARR_SIZE);
    new_flow->ts_sec[new_flow->packet_count] = pkthdr->ts.tv_sec;
    new_flow->ts_msec[new_flow->packet_count] = pkthdr->ts.tv_usec;
    if (new_flow->ts_sec == NULL || new_flow->ts_msec == NULL)
    {
        perror("there is a problem allocating memory");
    }
    new_flow->fwd++;
    if (new_flow->fwd_hdr_min > tcp_hdr_size || new_flow->fwd_hdr_min == 0)
        new_flow->fwd_hdr_min = tcp_hdr_size;

    if (new_flow->fwd_hdr_max < tcp_hdr_size)
        new_flow->fwd_hdr_max = tcp_hdr_size;

    if (new_flow->fwd_pkts_payload_min > payload_size || new_flow->fwd_pkts_payload_min == 0)
        new_flow->fwd_pkts_payload_min = payload_size;

    if (new_flow->fwd_pkts_payload_max < payload_size)
        new_flow->fwd_hdr_max = payload_size;

    if (check_flag(tcp_hdr->th_flags, F_URG))
        new_flow->URG_fwd_count++;
    if (check_flag(tcp_hdr->th_flags, F_PSH))
        new_flow->PSH_fwd_count++;
    if (check_flag(tcp_hdr->th_flags, F_FIN))
        new_flow->FIN_count++;
    if (check_flag(tcp_hdr->th_flags, F_SYN))
        new_flow->SYN_count++;
    if (check_flag(tcp_hdr->th_flags, F_RST))
        new_flow->RST_count++;
    if (check_flag(tcp_hdr->th_flags, F_ACK))
        new_flow->ACK_count++;
    if (check_flag(tcp_hdr->th_flags, F_ECE))
        new_flow->ECE_count++;
    if (check_flag(tcp_hdr->th_flags, F_CWR))
        new_flow->CWR_count++;
    new_flow->packet_count++;
    return new_flow;
}

void tcp_update_flow(
    FlowInfo *flow,
    const unsigned char *packet,
    const struct pcap_pkthdr *pkthdr)
{
    const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ethhdr));
    const struct ethhdr *eth_hdr = (struct ethhdr *)packet;
    const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_hdr->ip_hl * 4);
    int tcp_hdr_size = tcp_hdr->th_off * 4;
    int ip_hdr_size = ip_hdr->ip_hl * 4;
    int payload_size = ip_hdr->ip_len - ip_hdr_size - tcp_hdr_size;
    bool is_fwd = flow->src_ip.s_addr == ip_hdr->ip_src.s_addr;
    int flow_packet_count = flow->packet_count;
    if (is_fwd)
    {
        flow->fwd++;
    }
    else
    {
        flow->bwd++;
    }
    if (flow_packet_count > ARR_SIZE)
    {
        // allocate new size
        ARR_SIZE *= 2;
        printf("allocating memory for : %d byte", flow->packet_count * 2);
        flow->ts_sec = realloc(flow->ts_sec, sizeof(long) * ARR_SIZE*2);
        flow->ts_msec = realloc(flow->ts_msec, sizeof(long) * ARR_SIZE*2);
        // ARR_SIZE = flow->packet_count * 2;
        if (flow->ts_sec == NULL || flow->ts_msec == NULL)
        {
            perror("there is a problem allocating memory");
        }
    }
    *(flow->ts_sec + (long)flow_packet_count) = (long)pkthdr->ts.tv_sec;
    *(flow->ts_msec + (long)flow_packet_count) = (long)pkthdr->ts.tv_usec;
    is_fwd = true;
    if (is_fwd)
    {
        flow->fwd++;
        if (flow->fwd_hdr_min > tcp_hdr_size || flow->fwd_hdr_min == 0)
            flow->fwd_hdr_min = tcp_hdr_size;

        if (flow->fwd_hdr_max < tcp_hdr_size)
            flow->fwd_hdr_max = tcp_hdr_size;

        if (flow->fwd_pkts_payload_min > payload_size || flow->fwd_pkts_payload_min == 0)
            flow->fwd_pkts_payload_min = payload_size;

        if (flow->fwd_pkts_payload_max < payload_size)
            flow->fwd_hdr_max = payload_size;

        if (check_flag(tcp_hdr->th_flags, F_URG))
            flow->URG_fwd_count++;
        if (check_flag(tcp_hdr->th_flags, F_PSH))
            flow->PSH_fwd_count++;
        if (check_flag(tcp_hdr->th_flags, F_FIN)){
            flow->FIN_count++;
            printFlowInfo(flow);
        }
        if (check_flag(tcp_hdr->th_flags, F_SYN))
            flow->SYN_count++;
        if (check_flag(tcp_hdr->th_flags, F_RST)){
            flow->RST_count++;
            // printFlowInfo(flow);
        }
        if (check_flag(tcp_hdr->th_flags, F_ACK))
            flow->ACK_count++;
        if (check_flag(tcp_hdr->th_flags, F_ECE))
            flow->ECE_count++;
        if (check_flag(tcp_hdr->th_flags, F_CWR))
            flow->CWR_count++;
        ;
    }
    else
    {
        flow->bwd++;
        if (flow->bwd_hdr_min > tcp_hdr_size || flow->bwd_hdr_min == 0)
            flow->bwd_hdr_min = tcp_hdr_size;

        if (flow->bwd_hdr_max < tcp_hdr_size)
            flow->bwd_hdr_max = tcp_hdr_size;

        if (flow->bwd_pkts_payload_min > payload_size || flow->bwd_pkts_payload_min == 0)
            flow->bwd_pkts_payload_min = payload_size;

        if (flow->bwd_pkts_payload_max < payload_size)
            flow->bwd_hdr_max = payload_size;

        if (check_flag(tcp_hdr->th_flags, F_PSH))
            flow->PSH_bwd_count++;
        if (check_flag(tcp_hdr->th_flags, F_URG))
            flow->URG_bwd_count++;
        if (check_flag(tcp_hdr->th_flags, F_FIN))
            flow->FIN_count++;
        if (check_flag(tcp_hdr->th_flags, F_SYN))
            flow->SYN_count++;
        if (check_flag(tcp_hdr->th_flags, F_RST))
            flow->RST_count++;
        if (check_flag(tcp_hdr->th_flags, F_ACK))
            flow->ACK_count++;
        if (check_flag(tcp_hdr->th_flags, F_ECE))
            flow->ECE_count++;
        if (check_flag(tcp_hdr->th_flags, F_CWR))
            flow->CWR_count++;
    }
    flow->packet_count++;
}

#endif