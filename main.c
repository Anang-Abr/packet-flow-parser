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

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10
#define F_URG 0x20
#define F_ECE 0x40
#define F_CWR 0x80


#define MAX_FLOWS 10
#define MAX_PACKETS 30


FlowInfo flows[MAX_FLOWS];
int flow_count = 0;
int packet_count = 0;
char protocol = 'O';
int tcp_flow = 0;
int udp_flow = 0;
int TEMP_ARR_SIZE = 10;
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

bool check_flag( uint8_t flag, uint8_t compare){
    return ((flag & compare) > 0);
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    const struct ethhdr *eth_header = (struct ethhdr *)packet;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    uint16_t dport, sport;
    
    //PROTOCOL TCP
    if (ip_header->ip_p == IPPROTO_TCP)
    {
        const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
        sport = ntohs(tcp_header->th_sport);
        dport = ntohs(tcp_header->th_dport);
        int index = find_flow_index(ip_header->ip_src, ip_header->ip_dst, sport, dport);
        int tcp_hdr_size = tcp_header->th_off * 4;
        int ip_hdr_size = ip_header->ip_hl * 4;
        int payload_size = ip_header->ip_len - ip_hdr_size - tcp_hdr_size;
        int flow_packet_count;
        bool is_fwd;
        if (index == -1){
            tcp_flow++;
            flow_packet_count = 0;
            flows[flow_count].src_ip = ip_header->ip_src;
            flows[flow_count].dst_ip = ip_header->ip_dst;
            flows[flow_count].src_port = ntohs(tcp_header->th_sport);
            flows[flow_count].dst_port = ntohs(tcp_header->th_dport);
            flows[flow_count].protocol = 'T';
            flows[flow_count].packet_count = 0;
            flows[flow_count].fwd = 0;
            flows[flow_count].bwd = 0;
            flows[flow_count].fwd_tot = tcp_hdr_size;
            flows[flow_count].bwd_tot = 0;
            flows[flow_count].fwd_hdr_min = 0;
            flows[flow_count].bwd_hdr_min = 0;
            flows[flow_count].fwd_hdr_max = 0;
            flows[flow_count].bwd_hdr_max = 0;
            flows[flow_count].fwd_pkts_payload_min = 0;
            flows[flow_count].FIN_count = 0;
            flows[flow_count].SYN_count = 0;
            flows[flow_count].PSH_fwd_count = 0;
            flows[flow_count].PSH_bwd_count = 0;
            flows[flow_count].ACK_count = 0;
            flows[flow_count].URG_fwd_count = 0;
            flows[flow_count].URG_bwd_count = 0;
            flows[flow_count].ECE_count = 0;
            flows[flow_count].CWR_count = 0;
            flows[flow_count].RST_count = 0;
            printf("allocating memory for : %ld byte", sizeof(long) * TEMP_ARR_SIZE);
            flows[flow_count].ts_sec = malloc(sizeof(long)*TEMP_ARR_SIZE);
            flows[flow_count].ts_msec = malloc(sizeof(long)*TEMP_ARR_SIZE);
            *(flows[flow_count].ts_sec) = 9786;
            *(flows[flow_count].ts_msec) = 9786;
            // *(flows[flow_count].ts_sec) = pkthdr->ts.tv_sec;
            // *(flows[flow_count].ts_msec) = pkthdr->ts.tv_usec;
            if (flows[flow_count].ts_sec == NULL || flows[flow_count].ts_msec == NULL)
            {  
                printf("there is a problem allocating memory");
            }
            is_fwd = true;
            if (is_fwd)
            {
                flows[flow_count].fwd++;
                if (flows[flow_count].fwd_hdr_min > tcp_hdr_size || flows[flow_count].fwd_hdr_min == 0)
                    flows[flow_count].fwd_hdr_min = tcp_hdr_size;

                if (flows[flow_count].fwd_hdr_max < tcp_hdr_size)
                    flows[flow_count].fwd_hdr_max = tcp_hdr_size;

                if (flows[flow_count].fwd_pkts_payload_min > payload_size || flows[flow_count].fwd_pkts_payload_min == 0)
                    flows[flow_count].fwd_pkts_payload_min = payload_size;
                    
                if (flows[flow_count].fwd_pkts_payload_max < payload_size)
                    flows[flow_count].fwd_hdr_max = payload_size;
                
                printf("flag: %X\n", tcp_header->th_flags);
                if(check_flag(tcp_header->th_flags, F_URG)) 
                    flows[flow_count].URG_fwd_count++;
                if(check_flag(tcp_header->th_flags, F_PSH))
                    flows[flow_count].PSH_fwd_count++;
                if(check_flag(tcp_header->th_flags, F_FIN)) 
                    flows[flow_count].FIN_count++;
                if(check_flag(tcp_header->th_flags, F_SYN))
                    flows[flow_count].SYN_count++;
                if(check_flag(tcp_header->th_flags, F_RST))
                    flows[flow_count].RST_count++;
                if(check_flag(tcp_header->th_flags, F_ACK))
                    flows[flow_count].ACK_count++;
                if(check_flag(tcp_header->th_flags, F_ECE)) 
                    flows[flow_count].ECE_count++;
                if(check_flag(tcp_header->th_flags, F_CWR))
                    flows[flow_count].CWR_count++;
                ;
            }
            else
            {
                flows[flow_count].bwd++;
                if (flows[flow_count].bwd_hdr_min > tcp_hdr_size || flows[flow_count].bwd_hdr_min == 0)
                    flows[flow_count].bwd_hdr_min = tcp_hdr_size;

                if (flows[flow_count].bwd_hdr_max < tcp_hdr_size)
                    flows[flow_count].bwd_hdr_max = tcp_hdr_size;

                if (flows[flow_count].bwd_pkts_payload_min > payload_size || flows[flow_count].bwd_pkts_payload_min == 0)
                    flows[flow_count].bwd_pkts_payload_min = payload_size;

                if (flows[flow_count].bwd_pkts_payload_max < payload_size)
                    flows[flow_count].bwd_hdr_max = payload_size;
                
                printf("flag: %X\n", tcp_header->th_flags);
                if (check_flag(tcp_header->th_flags, F_PSH))
                    flows[flow_count].PSH_bwd_count++;
                if (check_flag(tcp_header->th_flags, F_URG))
                    flows[flow_count].URG_bwd_count++;
                if(check_flag(tcp_header->th_flags, F_FIN)) 
                    flows[flow_count].FIN_count++;
                if(check_flag(tcp_header->th_flags, F_SYN))
                    flows[flow_count].SYN_count++;
                if(check_flag(tcp_header->th_flags, F_RST))
                    flows[flow_count].RST_count++;
                if(check_flag(tcp_header->th_flags, F_ACK))
                    flows[flow_count].ACK_count++;
                if(check_flag(tcp_header->th_flags, F_ECE)) 
                    flows[flow_count].ECE_count++;
                if(check_flag(tcp_header->th_flags, F_CWR))
                    flows[flow_count].CWR_count++;
            }

            printf("timestamp masuknya flow: %ld s \n", pkthdr->ts.tv_sec);
            printf("timestamp masuknya flow: %ld ms\n", pkthdr->ts.tv_usec);
            flows[flow_count].packet_count++;
            flow_count++;
            
            if (flows[flow_count].packet_count >= MAX_PACKETS)
            {
                pcap_breakloop((pcap_t *)user_data);
            }
        }

        // when the same flow is found, update flow information
        else{
            is_fwd = flows[index].src_ip.s_addr == ip_header->ip_src.s_addr;
            flow_packet_count = flows[index].packet_count;
            if(is_fwd){
                flows[index].fwd++;
            }else{
                flows[index].bwd++;
            }
            if(flow_packet_count > TEMP_ARR_SIZE){
                //allocate new size
                TEMP_ARR_SIZE *= 2;
                printf("allocating memory for : %ld byte", sizeof(long) * ((flow_packet_count/TEMP_ARR_SIZE+1)*10));
                flows[index].ts_sec  = realloc(flows[index].ts_sec , sizeof(long) * TEMP_ARR_SIZE);
                flows[index].ts_msec = realloc(flows[index].ts_msec, sizeof(long) * TEMP_ARR_SIZE);
                if (flows[index].ts_sec == NULL || flows[index].ts_msec == NULL)
                {
                    printf("there is a problem allocating memory");
                }
            }
            printf("paket ke-%d dengan ts: %ld\n", flow_packet_count, pkthdr->ts.tv_sec);
            *(flows[index].ts_sec + (long)flow_packet_count) = (long)pkthdr->ts.tv_sec;
            *(flows[index].ts_msec + (long)flow_packet_count) = (long)pkthdr->ts.tv_sec;
            is_fwd = true;
            if (is_fwd)
            {
                flows[index].fwd++;
                if (flows[index].fwd_hdr_min > tcp_hdr_size || flows[index].fwd_hdr_min == 0)
                    flows[index].fwd_hdr_min = tcp_hdr_size;

                if (flows[index].fwd_hdr_max < tcp_hdr_size)
                    flows[index].fwd_hdr_max = tcp_hdr_size;

                if (flows[index].fwd_pkts_payload_min > payload_size || flows[index].fwd_pkts_payload_min == 0)
                    flows[index].fwd_pkts_payload_min = payload_size;

                if (flows[index].fwd_pkts_payload_max < payload_size)
                    flows[index].fwd_hdr_max = payload_size;

                printf("flag: %X\n", tcp_header->th_flags);
                if (check_flag(tcp_header->th_flags, F_URG))
                    flows[index].URG_fwd_count++;
                if (check_flag(tcp_header->th_flags, F_PSH))
                    flows[index].PSH_fwd_count++;
                if (check_flag(tcp_header->th_flags, F_FIN))
                    flows[index].FIN_count++;
                if (check_flag(tcp_header->th_flags, F_SYN))
                    flows[index].SYN_count++;
                if (check_flag(tcp_header->th_flags, F_RST))
                    flows[index].RST_count++;
                if (check_flag(tcp_header->th_flags, F_ACK))
                    flows[index].ACK_count++;
                if (check_flag(tcp_header->th_flags, F_ECE))
                    flows[index].ECE_count++;
                if (check_flag(tcp_header->th_flags, F_CWR))
                    flows[index].CWR_count++;
                ;
            }
            else
            {
                flows[index].bwd++;
                if (flows[index].bwd_hdr_min > tcp_hdr_size || flows[index].bwd_hdr_min == 0)
                    flows[index].bwd_hdr_min = tcp_hdr_size;

                if (flows[index].bwd_hdr_max < tcp_hdr_size)
                    flows[index].bwd_hdr_max = tcp_hdr_size;

                if (flows[index].bwd_pkts_payload_min > payload_size || flows[index].bwd_pkts_payload_min == 0)
                    flows[index].bwd_pkts_payload_min = payload_size;

                if (flows[index].bwd_pkts_payload_max < payload_size)
                    flows[index].bwd_hdr_max = payload_size;

                printf("flag: %X\n", tcp_header->th_flags);
                if (check_flag(tcp_header->th_flags, F_PSH))
                    flows[index].PSH_bwd_count++;
                if (check_flag(tcp_header->th_flags, F_URG))
                    flows[index].URG_bwd_count++;
                if (check_flag(tcp_header->th_flags, F_FIN))
                    flows[index].FIN_count++;
                if (check_flag(tcp_header->th_flags, F_SYN))
                    flows[index].SYN_count++;
                if (check_flag(tcp_header->th_flags, F_RST))
                    flows[index].RST_count++;
                if (check_flag(tcp_header->th_flags, F_ACK))
                    flows[index].ACK_count++;
                if (check_flag(tcp_header->th_flags, F_ECE))
                    flows[index].ECE_count++;
                if (check_flag(tcp_header->th_flags, F_CWR))
                    flows[index].CWR_count++;
            }

            printf("timestamp masuknya flow: %ld s \n", pkthdr->ts.tv_sec);
            printf("timestamp masuknya flow: %ld ms\n", pkthdr->ts.tv_usec);
            flows[index].packet_count++;
            if (flows[index].packet_count >= MAX_PACKETS)
            {
                pcap_breakloop((pcap_t *)user_data);
            }
        }
    }
    //PROTOCOL UDP
    else if (ip_header->ip_p == IPPROTO_UDP)
    {
        // udp_handler(pkthdr, packet);
        printf("================================================================ + satu udp, total:: %d", udp_flow);
        const struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
        int index = find_flow_index(ip_header->ip_src, ip_header->ip_dst, sport, dport);
        if(index == -1){
            udp_flow++;
            flows[flow_count].src_ip = ip_header->ip_src;
            flows[flow_count].dst_ip = ip_header->ip_dst;
            flows[flow_count].src_port = ntohs(udp_header->uh_sport);
            flows[flow_count].dst_port = ntohs(udp_header->uh_dport);
            flows[flow_count].protocol = 'U';
            flows[flow_count].packet_count = 0;
            flows[flow_count].packet_count++;
            flow_count++;
                printf("================================================================ + %d udp, count:: %d", flow_count, flows[flow_count].packet_count);
            if (flows[flow_count].packet_count >= MAX_PACKETS)
            {
                pcap_breakloop((pcap_t *)user_data);
            }
        }else{
            flows[index].src_ip = ip_header->ip_src;
            flows[index].dst_ip = ip_header->ip_dst;
            flows[index].src_port = ntohs(udp_header->uh_sport);
            flows[index].dst_port = ntohs(udp_header->uh_dport);
            flows[index].protocol = 'T';
            flows[flow_count].packet_count++;
            printf("================================================================ + satu udp, count:: %d", flows[index].packet_count);
            if (flows[index].packet_count >= MAX_PACKETS)
            {
                pcap_breakloop((pcap_t *)user_data);
            }
        }
    }
    else{
        printf("else, protocol:%d", ip_header->ip_p);
    }
    // packet_count++;
    printf("\n");
    pcap_dump((u_char *)pcap_dumper, pkthdr, packet);
    if (flow_count >= MAX_FLOWS)
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
    printf("Total UDP Flowss: %d\n", udp_flow);
    printf("Total TCP Flows: %d\n", tcp_flow);


    //feel free to move or delete this since it's just for logging purpose

    for (int i = 0; i < flow_count; i++)
    {
        // tempJson = cJSON_CreateObject();
        // tsArr = cJSON_CreateArray();
        // payloadArr = cJSON_CreateArray();
        // cJSON_AddStringToObject(tempJson, "src_ip", inet_ntoa(flows[i].src_ip));
        // cJSON_AddStringToObject(tempJson, "dst_ip", inet_ntoa(flows[i].dst_ip));
        // cJSON_AddNumberToObject(tempJson, "src_port", flows[i].src_port);
        // cJSON_AddNumberToObject(tempJson, "dst_port", flows[i].dst_port);
        // cJSON_AddNumberToObject(tempJson, "pkt_sum", flows[i].packet_count);
        // cJSON_AddNumberToObject(tempJson, "protocol", flows[i].protocol);
        // cJSON_AddNumberToObject(tempJson, "fwd_tot", flows[i].fwd_tot);
        // cJSON_AddNumberToObject(tempJson, "bwd_tot", flows[i].bwd_tot);
        // cJSON_AddNumberToObject(tempJson, "fwd", flows[i].fwd);
        // cJSON_AddNumberToObject(tempJson, "bwd_tot",flows[i].bwd);
        if(flows[i].protocol == 'T'){
            printf("[");
            for (int j = 0; j < flows[i].packet_count ; j++)
            {
                // cJSON_AddItemToArray(tsArr, cJSON_CreateNumber(*(flows[i].ts_sec + j)));
                // printf("%ld,", *(flows[i].ts_sec + j));
                
                    // printf("%p,\n", flows[i].ts_sec + j);
                    // printf("%p, : %ld\n", flows[i].ts_sec + j, *(flows[i].ts_sec + j));
                printf("%ld,", *(flows[i].ts_sec + j));
                
            }
            printf("]\n");
        }
        // cJSON_AddItemToObject(tempJson, "ts_sec_arr", tsArr);
        // cJSON_AddItemToArray(flowArr, tempJson);
        // printf("flow array: %s", cJSON_Print(tempJson));
        printf("%d-th flow packet count: %d\n",i,  flows[i].packet_count);
        // if(flows[i].ts_sec != NULL){
        //     printf("alamat pada packet ke-%d : %ln", i, flows[i].ts_sec);
        //     free(flows[i].ts_sec);
        //     flows[i].ts_sec = NULL;
        // }
        // if (flows[i].ts_msec != NULL)
        // {
        //     printf("alamat pada packet ke-%d : %ln", i, flows[i].ts_msec);
        //     free(flows[i].ts_msec);
        //     flows[i].ts_msec = NULL;
        // }
    }
    fclose;
    return 0;
}