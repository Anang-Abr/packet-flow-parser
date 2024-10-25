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
#include "../main.h"
#include "../utils/cJSON.h"

int ARR_SIZE = 100;


/** TODO
 * Find why the exported count is higher than tcp captured
 */

// exporting the flow info to the output file
void printFlowInfo(FlowInfo *f)
{
    packet_processed += f->packet_count;
    if (f->packet_count == 0)
        packet_processed++;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(f->src_ip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(f->dst_ip), dst_ip, INET_ADDRSTRLEN);
    if (fptr != NULL)
    {
        if (
            fprintf(fptr,
                    "{ \"id\" : %d, \"src_ip\" : \"%s\", \"dst_ip\" : \"%s\",\"src_port\" : %d, \"dst_port\" : %d, \"packet_count\" : %d, \"fwd\" : %d, \"fwd_hdr_min\" : %d, \"fwd_hdr_max\" : %d, \"fwd_payload_min\" : %d, \"fwd_payload_max\" : %d, \"fwd_payload_tot\" : %ld, \"bwd\" : %d, \"bwd_hdr_min\" : %d, \"bwd_hdr_max\" : %d, \"bwd_payload_min\" : %d, \"bwd_payload_max\" : %d, \"bwd_payload_tot\" : %ld, \"FIN_count\" : %d, \"SYN_count\" : %d, \"ACK_count\" : %d, \"ECE_count\" : %d, \"CWR_count\" : %d, \"RST_count\" : %d, \"URG_fwd_count\" : %d, \"URG_bwd_count\" : %d, \"PSH_fwd_count\" : %d, \"PSH_bwd_count\" : %d,\n",
                    ++count, src_ip, dst_ip, f->src_port, f->dst_port, f->packet_count, f->fwd, f->fwd_hdr_min, f->fwd_hdr_max, f->fwd_payload_min, f->fwd_payload_max, f->fwd_payload_tot, f->bwd, f->bwd_hdr_min, f->bwd_hdr_max, f->bwd_payload_min, f->bwd_payload_max, f->bwd_payload_tot, f->FIN_count, f->SYN_count, f->ACK_count, f->ECE_count, f->CWR_count, f->RST_count, f->URG_fwd_count, f->URG_bwd_count, f->PSH_fwd_count, f->PSH_bwd_count) < 0)
        {
            perror("error writing to file");
            exit(EXIT_FAILURE);
        }

        fprintf(fptr, "  \"ts_sec\": [");
        for (int i = 0; i < f->packet_count; i++)
        {
            fprintf(fptr, "%ld", f->ts_sec[i]);
            if (i < f->packet_count - 1)
            {
                fprintf(fptr, ", ");
            }
        }
        fprintf(fptr, "],\n");

        fprintf(fptr, "  \"ts_msec\": [");
        for (int i = 0; i < f->packet_count; i++)
        {
            fprintf(fptr, "%ld", f->ts_msec[i]);
            if (i < f->packet_count - 1)
            {
                fprintf(fptr, ", ");
            }
        }
        fprintf(fptr, "],\n");

        fprintf(fptr, "  \"payloads\": [");
        for (int i = 0; i < f->packet_count; i++)
        {
            fprintf(fptr, "%zu", f->payloads_size[i]);
            if (i < f->packet_count - 1)
            {
                fprintf(fptr, ", ");
            }
        }
        fprintf(fptr, "]\n");

        fprintf(fptr, "},\n");
    }
    else
    {
        if (
            printf(
                "{ \"id\" : %d, \"src_ip\" : \"%s\", \"dst_ip\" : \"%s\",\"src_port\" : %d, \"dst_port\" : %d, \"packet_count\" : %d, \"fwd\" : %d, \"fwd_hdr_min\" : %d, \"fwd_hdr_max\" : %d, \"fwd_payload_min\" : %d, \"fwd_payload_max\" : %d, \"fwd_payload_tot\" : %ld, \"bwd\" : %d, \"bwd_hdr_min\" : %d, \"bwd_hdr_max\" : %d, \"bwd_payload_min\" : %d, \"bwd_payload_max\" : %d, \"bwd_payload_tot\" : %ld, \"FIN_count\" : %d, \"SYN_count\" : %d, \"ACK_count\" : %d, \"ECE_count\" : %d, \"CWR_count\" : %d, \"RST_count\" : %d, \"URG_fwd_count\" : %d, \"URG_bwd_count\" : %d, \"PSH_fwd_count\" : %d, \"PSH_bwd_count\" : %d,\n",
                ++count, src_ip, dst_ip, f->src_port, f->dst_port, f->packet_count, f->fwd, f->fwd_hdr_min, f->fwd_hdr_max, f->fwd_payload_min, f->fwd_payload_max, f->fwd_payload_tot, f->bwd, f->bwd_hdr_min, f->bwd_hdr_max, f->bwd_payload_min, f->bwd_payload_max, f->bwd_payload_tot, f->FIN_count, f->SYN_count, f->ACK_count, f->ECE_count, f->CWR_count, f->RST_count, f->URG_fwd_count, f->URG_bwd_count, f->PSH_fwd_count, f->PSH_bwd_count) < 0)
        {
            perror("error writing to file");
            exit(EXIT_FAILURE);
        }

        printf("  \"ts_sec\": [");
        for (int i = 0; i < f->packet_count; i++)
        {
            printf( "%ld", f->ts_sec[i]);
            if (i < f->packet_count - 1)
            {
                printf( ", ");
            }
        }
        printf( "],\n");

        printf( "  \"ts_msec\": [");
        for (int i = 0; i < f->packet_count; i++)
        {
            printf( "%ld", f->ts_msec[i]);
            if (i < f->packet_count - 1)
            {
                printf( ", ");
            }
        }
        printf( "],\n");

        printf( "  \"payloads\": [");
        for (int i = 0; i < f->packet_count; i++)
        {
            printf( "%zu", f->payloads_size[i]);
            if (i < f->packet_count - 1)
            {
                printf( ", ");
            }
        }
        printf( "]\n");

        printf( "},\n");
    }
    enqueue(queueBuffer, f);
}

// check the tcp flag
bool check_flag(uint8_t flag, uint8_t compare)
{
    return ((flag & compare) > 0);
}

// find flow in the flow buffer
FlowInfo *find_flow_index(
    FlowsBuffer *flowBuffer,
    const struct in_addr src_ip,
    const struct in_addr dst_ip,
    const uint16_t src_port,
    const uint16_t dst_port)
{
    FlowInfo *foundFlow = queueSearch(queueBuffer, src_ip, dst_ip, src_port, dst_port);
    if (foundFlow != NULL)
    {
        return NULL;
    }
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
    if (fb->count >= fb->capacity)
    {
        fb->capacity *= 2;
        FlowInfo *temp_flows = realloc(fb->flows, sizeof(FlowInfo) * fb->capacity);

        // Check if reallocation was successful
        if (temp_flows == NULL)
        {
            // Handle reallocation failure

            // Free the original pointer
            free(fb->flows);

            // You might choose to exit here or handle the error in another way
            perror("Failed to reallocate memory for FlowsBuffer");
            exit(EXIT_FAILURE);
        }

        // Assign the reallocated memory back to the original pointer
        fb->flows = temp_flows;
    }
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    const struct ethhdr *eth_header = (struct ethhdr *)packet;
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
    FlowInfo *found_flow = find_flow_index(fb, ip_header->ip_src, ip_header->ip_dst, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
    int flow_packet_count;
    if (found_flow == NULL)
    {
        flow_count++;
        found_flow = dequeue(queueBuffer);
        if (found_flow == NULL)
        {
            tcp_generate_new_flow(fb, packet, pkthdr);
            fb->count++;
        }
        else
        {
            reuse_flow(found_flow, packet, pkthdr);
        }
    }
    // when the same flow is found, update flow information
    else
    {
        tcp_update_flow(found_flow, packet, pkthdr);
    }
}

FlowInfo *tcp_generate_new_flow(
    FlowsBuffer *fbs,
    const unsigned char *packet,
    const struct pcap_pkthdr *pkthdr)
{
    FlowInfo *new_flow = &fbs->flows[fbs->count];
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
    new_flow->fwd_hdr_min = 0;
    new_flow->bwd_hdr_min = 0;
    new_flow->fwd_hdr_max = 0;
    new_flow->bwd_hdr_max = 0;
    new_flow->fwd_payload_min = 0;
    new_flow->fwd_payload_max = 0;
    new_flow->bwd_payload_min = 0;
    new_flow->bwd_payload_max = 0;
    new_flow->fwd_payload_tot = 0;
    new_flow->bwd_payload_tot = 0;
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
    new_flow->capacity = 10;
    new_flow->ts_sec = (long *)malloc(sizeof(long) * new_flow->capacity);
    new_flow->ts_msec = (long *)malloc(sizeof(long) * new_flow->capacity);
    new_flow->payloads_size = (long *)malloc(sizeof(long) * new_flow->capacity);
    new_flow->ts_sec[new_flow->packet_count] = pkthdr->ts.tv_sec;
    new_flow->ts_msec[new_flow->packet_count] = pkthdr->ts.tv_usec;
    new_flow->payloads_size[new_flow->packet_count] = payload_size;
    new_flow->fwd++;
    new_flow->packet_count++;
    new_flow->hasFin = false;
    new_flow->waitACK = false;
    if (new_flow->ts_sec == NULL || new_flow->ts_msec == NULL || new_flow->payloads_size == NULL)
    {
        if (new_flow->ts_sec)
            free(new_flow->ts_sec);
        if (new_flow->ts_msec)
            free(new_flow->ts_msec);
        if (new_flow->payloads_size)
            free(new_flow->payloads_size);
        perror("there is a problem allocating memory");
    }
    if (new_flow->fwd_hdr_min > tcp_hdr_size || new_flow->fwd_hdr_min == 0)
        new_flow->fwd_hdr_min = tcp_hdr_size;

    if (new_flow->fwd_hdr_max < tcp_hdr_size)
        new_flow->fwd_hdr_max = tcp_hdr_size;

    if (new_flow->fwd_payload_min > payload_size || new_flow->fwd_payload_min == 0)
        new_flow->fwd_payload_min = payload_size;

    if (new_flow->fwd_payload_max < payload_size)
        new_flow->fwd_payload_max = payload_size;
    new_flow->fwd_payload_tot += payload_size;
    if (check_flag(tcp_hdr->th_flags, F_URG))
    {
        new_flow->URG_fwd_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_PSH))
    {
        new_flow->PSH_fwd_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_FIN))
    {
        new_flow->FIN_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_SYN))
    {
        new_flow->SYN_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_ACK))
    {
        new_flow->ACK_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_ECE))
    {
        new_flow->ECE_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_CWR))
    {
        new_flow->CWR_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_RST))
    {
        new_flow->RST_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_RST))
    {
        printFlowInfo(new_flow);
    }
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
    unsigned int tcp_hdr_size = tcp_hdr->th_off * 4;
    unsigned int ip_hdr_size = ip_hdr->ip_hl * 4;
    unsigned int payload_size = ip_hdr->ip_len - ip_hdr_size - tcp_hdr_size;
    bool is_fwd = flow->src_ip.s_addr == ip_hdr->ip_src.s_addr;
    int flow_packet_count = flow->packet_count;
    flow->packet_count++;
    bool exported = false;
    if (flow_packet_count >= flow->capacity)
    {
        // allocate new size
        flow->capacity *= 2;
        long *temp_ts_sec = realloc(flow->ts_sec, sizeof(long) * flow->capacity);
        long *temp_ts_msec = realloc(flow->ts_msec, sizeof(long) * flow->capacity);
        long *temp_payloads_size = realloc(flow->payloads_size, sizeof(long) * flow->capacity);

        // Check if any reallocation failed
        if (temp_ts_sec == NULL || temp_ts_msec == NULL || temp_payloads_size == NULL)
        {
            perror("Failed to reallocate memory for flow timestamps or payload sizes");

            // Clean up successfully reallocated memory to prevent memory leaks
            if (temp_ts_sec)
            {
                free(temp_ts_sec);
            }
            if (temp_ts_msec)
            {
                free(temp_ts_msec);
            }
            if (temp_payloads_size)
            {
                free(temp_payloads_size);
            }

            // You can also free the original memory here if you want to exit, to ensure no memory is leaked
            free(flow->ts_sec);
            free(flow->ts_msec);
            free(flow->payloads_size);

            exit(EXIT_FAILURE);
        }

        // Assign the successfully reallocated memory back to the original pointers
        flow->ts_sec = temp_ts_sec;
        flow->ts_msec = temp_ts_msec;
        flow->payloads_size = temp_payloads_size;
    }
    flow->ts_sec[flow_packet_count] = (long)pkthdr->ts.tv_sec;
    flow->ts_msec[flow_packet_count] = (long)pkthdr->ts.tv_usec;
    flow->payloads_size[flow_packet_count] = (long)payload_size;
    if (is_fwd)
    {
        flow->fwd++;
        if (flow->fwd_hdr_min > tcp_hdr_size || flow->fwd_hdr_min == 0)
            flow->fwd_hdr_min = tcp_hdr_size;

        if (flow->fwd_hdr_max < tcp_hdr_size)
            flow->fwd_hdr_max = tcp_hdr_size;

        if (flow->fwd_payload_min > payload_size || flow->fwd_payload_min == 0)
            flow->fwd_payload_min = payload_size;

        if (flow->fwd_payload_max < payload_size)
            flow->fwd_payload_max = payload_size;

        flow->fwd_payload_tot += payload_size;
        if (check_flag(tcp_hdr->th_flags, F_URG))
        {
            flow->URG_fwd_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_PSH))
        {
            flow->PSH_fwd_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_SYN))
        {
            flow->SYN_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_ECE))
        {
            flow->ECE_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_CWR))
        {
            flow->CWR_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_ACK))
        {
            flow->ACK_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_FIN))
        {
            flow->FIN_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_RST))
        {
            flow->RST_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_ACK))
        {
            if (flow->waitACK)
            {
                printFlowInfo(flow);
                return;
            }
        }
        if (check_flag(tcp_hdr->th_flags, F_FIN))
        {
            if (flow->hasFin)
            {
                flow->waitACK = true;
            }
            flow->hasFin = true;
        }
        if (check_flag(tcp_hdr->th_flags, F_RST))
        {
            printFlowInfo(flow);
            return;
        }
    }
    else
    {
        flow->bwd++;
        if (flow->bwd_hdr_min > tcp_hdr_size || flow->bwd_hdr_min == 0)
            flow->bwd_hdr_min = tcp_hdr_size;

        if (flow->bwd_hdr_max < tcp_hdr_size)
            flow->bwd_hdr_max = tcp_hdr_size;

        if (flow->bwd_payload_min > payload_size || flow->bwd_payload_min == 0)
            flow->bwd_payload_min = payload_size;

        if (flow->bwd_payload_max < payload_size)
            flow->bwd_payload_max = payload_size;

        flow->bwd_payload_tot += payload_size;

        if (check_flag(tcp_hdr->th_flags, F_URG))
        {
            flow->URG_fwd_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_PSH))
        {
            flow->PSH_fwd_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_SYN))
        {
            flow->SYN_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_ECE))
        {
            flow->ECE_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_CWR))
        {
            flow->CWR_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_ACK))
        {
            flow->ACK_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_FIN))
        {
            flow->FIN_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_RST))
        {
            flow->RST_count++;
        }
        if (check_flag(tcp_hdr->th_flags, F_ACK))
        {
            if (flow->waitACK)
            {
                printFlowInfo(flow);
                return;
            }
        }
        if (check_flag(tcp_hdr->th_flags, F_FIN))
        {
            if (flow->hasFin)
            {
                flow->waitACK = true;
            }
            flow->hasFin = true;
        }
        if (check_flag(tcp_hdr->th_flags, F_RST))
        {
            printFlowInfo(flow);
            return;
        }
    }
}

void reuse_flow(
    FlowInfo *rf,
    const unsigned char *packet,
    const struct pcap_pkthdr *pkthdr)
{
    const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ethhdr));
    const struct ethhdr *eth_hdr = (struct ethhdr *)packet;
    const struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_hdr->ip_hl * 4);
    int tcp_hdr_size = tcp_hdr->th_off * 4;
    int ip_hdr_size = ip_hdr->ip_hl * 4;
    int payload_size = ip_hdr->ip_len - ip_hdr_size - tcp_hdr_size;
    rf->src_ip = ip_hdr->ip_src;
    rf->dst_ip = ip_hdr->ip_dst;
    rf->src_port = ntohs(tcp_hdr->th_sport);
    rf->dst_port = ntohs(tcp_hdr->th_dport);
    rf->protocol = 'T';
    rf->packet_count = 0;
    rf->fwd = 0;
    rf->bwd = 0;
    rf->fwd_hdr_min = 0;
    rf->bwd_hdr_min = 0;
    rf->fwd_hdr_max = 0;
    rf->bwd_hdr_max = 0;
    rf->fwd_payload_min = 0;
    rf->fwd_payload_max = 0;
    rf->bwd_payload_min = 0;
    rf->bwd_payload_max = 0;
    rf->fwd_payload_tot = 0;
    rf->FIN_count = 0;
    rf->SYN_count = 0;
    rf->PSH_fwd_count = 0;
    rf->PSH_bwd_count = 0;
    rf->ACK_count = 0;
    rf->URG_fwd_count = 0;
    rf->URG_bwd_count = 0;
    rf->ECE_count = 0;
    rf->CWR_count = 0;
    rf->RST_count = 0;
    rf->capacity = 10;
    if (rf->ts_sec)
        free(rf->ts_sec);
    if (rf->ts_msec)
        free(rf->ts_msec);
    if (rf->payloads_size)
        free(rf->payloads_size);
    rf->ts_sec = malloc(sizeof(long) * rf->capacity);
    rf->ts_msec = malloc(sizeof(long) * rf->capacity);
    rf->payloads_size = malloc(sizeof(long) * rf->capacity);
    rf->ts_sec[rf->packet_count] = pkthdr->ts.tv_sec;
    rf->ts_msec[rf->packet_count] = pkthdr->ts.tv_usec;
    rf->payloads_size[rf->packet_count] = payload_size;
    rf->packet_count++;
    rf->hasFin = false;
    rf->waitACK = false;
    if (rf->ts_sec == NULL || rf->ts_msec == NULL || rf->payloads_size == NULL)
    {
        if (rf->ts_sec)
            free(rf->ts_sec);
        if (rf->ts_msec)
            free(rf->ts_msec);
        if (rf->payloads_size)
            free(rf->payloads_size);
        perror("there is a problem allocating memory");
    }
    rf->fwd++;
    if (rf->fwd_hdr_min > tcp_hdr_size || rf->fwd_hdr_min == 0)
        rf->fwd_hdr_min = tcp_hdr_size;

    if (rf->fwd_hdr_max < tcp_hdr_size)
        rf->fwd_hdr_max = tcp_hdr_size;

    if (rf->fwd_payload_min > payload_size || rf->fwd_payload_min == 0)
        rf->fwd_payload_min = payload_size;

    if (rf->fwd_payload_max < payload_size)
        rf->fwd_payload_max = payload_size;
    rf->fwd_payload_tot += payload_size;
    if (check_flag(tcp_hdr->th_flags, F_URG))
    {
        rf->URG_fwd_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_PSH))
    {
        rf->PSH_fwd_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_FIN))
    {
        rf->FIN_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_SYN))
    {
        rf->SYN_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_ACK))
    {
        rf->ACK_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_ECE))
    {
        rf->ECE_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_CWR))
    {
        rf->CWR_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_RST))
    {
        rf->RST_count++;
    }
    if (check_flag(tcp_hdr->th_flags, F_RST))
    {
        printFlowInfo(rf);
    }
}

void reset_flow(FlowInfo *rf)
{
    rf->src_ip.s_addr = 0;
    rf->dst_ip.s_addr = 0;
    rf->src_port = 0;
    rf->dst_port = 0;
    rf->packet_count = 0;
    rf->fwd = 0;
    rf->bwd = 0;

    rf->fwd_hdr_min = 0;
    rf->bwd_hdr_min = 0;
    rf->fwd_hdr_max = 0;
    rf->bwd_hdr_max = 0;
    rf->fwd_payload_min = 0;
    rf->fwd_payload_max = 0;
    rf->bwd_payload_min = 0;
    rf->bwd_payload_max = 0;
    rf->fwd_payload_tot = 0;
    rf->bwd_payload_tot = 0;

    rf->FIN_count = 0;
    rf->SYN_count = 0;
    rf->PSH_fwd_count = 0;
    rf->PSH_bwd_count = 0;
    rf->ACK_count = 0;
    rf->URG_fwd_count = 0;
    rf->URG_bwd_count = 0;
    rf->ECE_count = 0;
    rf->CWR_count = 0;
    rf->RST_count = 0;

    if (rf->ts_sec)
        free(rf->ts_sec);
    if (rf->ts_msec)
        free(rf->ts_msec);
    if (rf->payloads_size)
        free(rf->payloads_size);
    rf->capacity = 10;
    rf->ts_sec = malloc(sizeof(long) * rf->capacity);
    rf->ts_msec = malloc(sizeof(long) * rf->capacity);
    rf->payloads_size = malloc(sizeof(long) * rf->capacity);
    if (rf->ts_sec == NULL || rf->ts_msec == NULL || rf->payloads_size == NULL)
    {
        if (rf->ts_sec)
            free(rf->ts_sec);
        if (rf->ts_msec)
            free(rf->ts_msec);
        if (rf->payloads_size)
            free(rf->payloads_size);
        perror("Error allocating memory");
        rf->ts_sec = NULL;
        rf->ts_msec = NULL;
        rf->payloads_size = NULL;
    }
    rf->hasFin = false;
    rf->waitACK = false;
}

#endif