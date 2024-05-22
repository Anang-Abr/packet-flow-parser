#include <stdio.h>
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

#define MAX_FLOWS 50
#define MAX_PACKETS 50



FlowInfo flows[MAX_FLOWS];
int flow_count = 0;
int packet_count = 0;
char protocol = 'O';
int tcp_flow = 0;
int udp_flow = 0;
pcap_dumper_t *pcap_dumper;

void process_packet(const u_char *packet, int payload_offset, int payload_length)
{
    printf("Payload: ");
    for (int i = payload_offset; i < payload_offset + payload_length; ++i)
    {
        printf("%02x ", packet[i]);
    }
    printf("\n");
}

int find_flow_index(
    const struct in_addr src_ip,
    const struct in_addr dst_ip,
    const uint16_t src_port,
    const uint16_t dst_port)
{
    for (int i = 0; i < flow_count; i++)
    {
        if ((
                flows[i].src_ip.s_addr == src_ip.s_addr &&
                flows[i].dst_ip.s_addr == dst_ip.s_addr &&
                flows[i].src_port == src_port &&
                flows[i].dst_port == dst_port) ||
            (flows[i].src_ip.s_addr == dst_ip.s_addr &&
             flows[i].dst_ip.s_addr == src_ip.s_addr &&
             flows[i].src_port == dst_port &&
             flows[i].dst_port == src_port))
        {
            return i;
        }
    }
    return -1;
}

void tcp_handler(const struct pcap_pkthdr *pkthdr, const unsigned char *packet){
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    const struct ethhdr *eth_header = (struct ethhdr *)packet;
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    char *src_eth = ether_ntoa((const struct ether_addr *)eth_header->h_source);
    char *dst_eth = ether_ntoa((const struct ether_addr *)eth_header->h_dest);
    int flow_index = find_flow_index(ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
    int tcp_hdr = tcp_header->th_off * 4;
    int payload_size = ip_header->ip_len - tcp_hdr;
    int payload_size2 = ip_header->ip_len - ip_header->ip_hl - tcp_hdr;
    printf("tcp header size: %d\n", tcp_hdr);
    printf("payload size1: %d\n", payload_size);
    printf("payload size2: %d\n", payload_size2);
    // new flow generated
    if (flow_index == -1)
    {
        if (flow_count < MAX_FLOWS)
        {
            flows[flow_count].src_ip = ip_header->ip_src;
            flows[flow_count].dst_ip = ip_header->ip_dst;
            flows[flow_count].src_port = ntohs(tcp_header->th_sport);
            flows[flow_count].dst_port = ntohs(tcp_header->th_dport);
            flows[flow_count].packet_count = 1;
            flows[flow_count].protocol = 'T';
            flows[flow_count].ts_start = pkthdr->ts.tv_sec;
            flows[flow_count].ts_last = pkthdr->ts.tv_sec;
            flows[flow_count].tms_start = pkthdr->ts.tv_usec;
            flows[flow_count].tms_last = pkthdr->ts.tv_usec;
            flows[flow_count].fwd_tot = 1;
            flows[flow_count].bwd_tot = 0;
            flows[flow_count].flow_ACK_flag_count = 0;
            flows[flow_count].flow_CWR_flag_count = 0;
            flows[flow_count].flow_ECE_flag_count = 0;
            flows[flow_count].flow_FIN_flag_count = 0;
            flows[flow_count].flow_RST_flag_count = 0;
            flows[flow_count].flow_SYN_flag_count = 0;
            flows[flow_count].pkt_array[flows[flow_count].packet_count-1] = pkthdr->len - sizeof(struct ethhdr);
            switch (tcp_header->th_flags)
            {
            case 0x01:
                printf("FIN\n");
                break;
            case 0x02:
                printf("SYN\n");
                break;
            case 0x04:
                printf("RST\n");
                break;
            case 0x08:
                printf("PSH\n");
                break;
            case 0x10:
                printf("ACK\n");
                break;
            case 0x20:
                printf("URG\n");
                break;
            case 0x40:
                printf("ECE\n");
                break;
            case 0x80:
                printf("CWR\n");
                break;
            case 0x11:
                printf("ACKFIN\n");
                break;
            default:
                printf("DEFAULT:%X\n", tcp_header->th_flags);
                break;
            }
            printf("timestamp masuknya flow: %ld\n", pkthdr->ts.tv_usec);
            flow_count++;
        }
        else
        {
            printf("Max flow count reached. Cannot add a new flow.\n");
        }
    }

    // update found flow
    else
    {
        flows[flow_index].packet_count++;
        flows[flow_index].ts_last = pkthdr->ts.tv_sec;
        flows[flow_index].tms_last = pkthdr->ts.tv_usec;
        flows[flow_index].tms_start = flows[flow_index].tms_start;
        flows[flow_index].pkt_array[flows[flow_index].packet_count-1] = pkthdr->len - sizeof(struct ethhdr);
        printf("packet ke- %d\n", flows[flow_index].packet_count);
        printf("array item: %ld\n", (pkthdr->len - sizeof(struct ethhdr)));
        switch (tcp_header->th_flags)
        {
        case 0x01:
            printf("FIN\n");
            break;
        case 0x02:
            printf("SYN\n");
            break;
        case 0x04:
            printf("RST\n");
            break;
        case 0x08:
            printf("PSH\n");
            break;
        case 0x10:
            printf("ACK\n");
            break;
        case 0x20:
            printf("URG\n");
            break;
        case 0x40:
            printf("ECE\n");
            break;
        case 0x80:
            printf("CWR\n");
            break;
        case 0x11:
            printf("ACKFIN\n");
            break;
        default:
            printf("DEFAULT:%X\n", tcp_header->th_flags);
            break;
        }
        // categorize between forward and backward packet
        if (flows[flow_index].src_ip.s_addr == ip_header->ip_src.s_addr)
        {
            flows[flow_index].fwd_tot++;
        }
        else
        {
            flows[flow_index].bwd_tot++;
        }
    }
    return;
}

void print_flow_info(int index){
    printf("Index %d:\n", index);
    printf("Flow %d:\n", index + 1);
    printf("Source IP: %s\n", inet_ntoa(flows[index].src_ip));
    printf("Destination IP: %s\n", inet_ntoa(flows[index].dst_ip));
    printf("Port Numbers: %d, %d\n", flows[index].src_port, flows[index].dst_port);
    printf("Packet Count: %d\n", flows[index].packet_count);
    printf("Protocol: %c\n", flows[index].protocol);
    printf("Timestamp(sec) start: %ld\n", flows[index].ts_start);
    printf("Timestamp(sec) last : %ld\n", flows[index].ts_last);
    printf("Timestamp(ms) start: %ld\n", flows[index].tms_start);
    printf("Timestamp(ms) last : %ld\n", flows[index].tms_last);
    printf("Forward :%d\n", flows[index].fwd_tot);
    printf("Bacward :%d\n", flows[index].bwd_tot);
    printf("packet count : %d\n", flows[index].packet_count);
    printf("array: [");
    for (int j = 0; j < sizeof(flows[index].pkt_array) / sizeof(int); j++)
    {
        printf("%d,",flows[index].pkt_array[j]);
    }
    printf("]\n");
    return;
}

void udp_handler(const struct pcap_pkthdr *pkthdr, const unsigned char *packet){
    const struct ethhdr *eth_header = (struct ethhdr *)packet;
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    printf("Packet captured\n");
    printf("Packet length: %d\n", pkthdr->len);
    printf("pkthdr length: %ld\n", sizeof(struct pcap_pkthdr));
    printf("Payload size pcap_pkthdr: %ld\n", pkthdr->len - sizeof(struct pcap_pkthdr));
    printf("Payload size ethhdr: %ld\n", pkthdr->len - sizeof(struct ethhdr));
    printf("Payload size ip_header: %ld\n", pkthdr->len - sizeof(ip_header));
    printf("Payload size ip_header: %ld\n", pkthdr->len - (sizeof(ip_header) + sizeof(struct ethhdr) + sizeof(struct pcap_pkthdr) + sizeof(struct tcphdr)));
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    char *src_eth = ether_ntoa((const struct ether_addr *)eth_header->h_source);
    char *dst_eth = ether_ntoa((const struct ether_addr *)eth_header->h_dest);
    printf("Source Host: %s\n", src_eth);
    printf("Destination Host: %s\n", dst_eth);
    printf("Layer 2 protocol: %d\n", eth_header->h_proto);
    printf("Source IP: %s\n", src_ip);
    printf("Destination Ip: %s\n", dst_ip);
    printf("TTL : %d\n", ip_header->ip_ttl);
    printf("TOS: %d\n", ip_header->ip_tos);
    const struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
    printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
    printf("Protocol: UDP\n");
    int flow_index = find_flow_index(ip_header->ip_src, ip_header->ip_dst, ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
    // membuat flow baru
    if (flow_index == -1)
    {
        if (flow_count < MAX_FLOWS)
        {
            flows[flow_count].src_ip = ip_header->ip_src;
            flows[flow_count].dst_ip = ip_header->ip_dst;
            flows[flow_count].src_port = ntohs(udp_header->uh_sport);
            flows[flow_count].dst_port = ntohs(udp_header->uh_dport);
            flows[flow_count].packet_count = 1;
            flows[flow_count].protocol = 'U';
            flows[flow_count].ts_start = pkthdr->ts.tv_sec;
            flows[flow_count].ts_last = pkthdr->ts.tv_sec;
            flows[flow_count].tms_start = pkthdr->ts.tv_usec;
            flows[flow_count].tms_last = pkthdr->ts.tv_usec;
            flows[flow_count].fwd_tot = 1;
            flows[flow_count].bwd_tot = 0;
            printf("timestamp masuknya flow: %ld\n", pkthdr->ts.tv_usec);
            flow_count++;
        }
        else
        {
            printf("Max flow count reached. Cannot add a new flow.\n");
        }
    }
    else
    {
        flows[flow_index].packet_count++;
        flows[flow_index].ts_last = pkthdr->ts.tv_sec;
        flows[flow_index].tms_last = pkthdr->ts.tv_usec;
    }
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    //PROTOCOL TCP
    if (ip_header->ip_p == IPPROTO_TCP)
    {
        tcp_handler(pkthdr, packet);
        process_packet(packet, 54, pkthdr->len - 54);
        
    }


    //PROTOCOL UDP
    else if (ip_header->ip_p == IPPROTO_UDP)
    {
        // udp_handler(pkthdr, packet);
    }
    packet_count++;
    printf("\n");
    pcap_dump((u_char *)pcap_dumper, pkthdr, packet);
    if (packet_count >= MAX_PACKETS)
    {
        pcap_breakloop((pcap_t *)user_data);
    }
}

/**
 * TODO
 * ? Install zeek flowmeter
*/

int main(int argc, char **argv)
{
    pcap_t *handle;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char s[64];
    size_t ret = strftime(s, sizeof(s), "captured_packets/%Y-%m-%d_%H-%M-%S.pcap", tm);
    assert(ret);
    FILE *pcapFile = fopen(s, "wb");
    fclose(pcapFile);
    char errbuf[PCAP_ERRBUF_SIZE];
    cJSON *flowArr = cJSON_CreateArray();
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }
    pcap_dumper = pcap_dump_open(handle, s);
    if (pcap_dumper == NULL)
    {
        printf("Error opening pcap file for writing.\n");
        return 1;
    }
    pcap_loop(handle, 0, packet_handler, (unsigned char *)handle);
    pcap_dump_close(pcap_dumper);
    pcap_close(handle);
    for (int k = 0; k < flow_count; k++)
    {
        if (flows[k].protocol == 'T')
        {
            tcp_flow += 1;
        }
        else
        {
            udp_flow += 1;
        }
    }
    // Print flow information
    for (int i = 0; i < flow_count; i++)
    {
        print_flow_info(i);
        cJSON *tempJson = cJSON_CreateObject();
        cJSON *tempArr = cJSON_CreateArray();
        cJSON_AddStringToObject(tempJson, "src_ip", inet_ntoa(flows[i].src_ip));
        cJSON_AddStringToObject(tempJson, "dst_ip", inet_ntoa(flows[i].dst_ip));
        cJSON_AddNumberToObject(tempJson, "src_port", flows[i].src_port);
        cJSON_AddNumberToObject(tempJson, "dst_port", flows[i].dst_port);
        cJSON_AddNumberToObject(tempJson, "pkt_sum", flows[i].packet_count);
        cJSON_AddNumberToObject(tempJson, "protocol", flows[i].protocol);
        cJSON_AddNumberToObject(tempJson, "ts_start", flows[i].ts_start);
        cJSON_AddNumberToObject(tempJson, "ts_last", flows[i].ts_last);
        cJSON_AddNumberToObject(tempJson, "tms_start", flows[i].tms_start);
        cJSON_AddNumberToObject(tempJson, "tms_last", flows[i].tms_last);
        cJSON_AddNumberToObject(tempJson, "fwd_tot", flows[i].fwd_tot);
        cJSON_AddNumberToObject(tempJson, "bwd_tot", flows[i].bwd_tot);
        for (int j = 0; j < sizeof(flows[i].pkt_array)/sizeof(int); j++)
        {
            cJSON_AddItemToArray(tempArr, cJSON_CreateNumber(flows[i].pkt_array[j]));
        }
        cJSON_AddItemToObject(tempJson, "payload_size_arr", tempArr);
        cJSON_AddItemToArray(flowArr, tempJson);
        printf("flow array: %s", cJSON_Print(tempJson));
        printf("\n");
    }


    printf("flow array: %s\n", cJSON_Print(flowArr));
    strftime(s, sizeof(s), "captured_packets/%Y-%m-%d_%H-%M-%S.json", tm);
    FILE *fp = fopen(s, "w");
    if(fp == NULL){
        printf("can't create file");
    }
    fputs(cJSON_Print(flowArr), fp);
    cJSON_Delete(flowArr);
    fclose;
    printf("Total UDP Flowss: %d\n", udp_flow);
    printf("Total TCP Flows: %d\n", tcp_flow);
    return 0;
}