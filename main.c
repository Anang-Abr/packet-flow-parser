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
#include <signal.h>
#include "flow.h"
#include "./handler/handler.h"
#include "main.h"

#define MAX_FLOWS 10
#define MAX_PACKETS 30

unsigned int flow_count = 0;
unsigned int packet_count = 0;
char protocol = 'O';
unsigned int tcp_flow = 0;
unsigned int udp_flow = 0;
pcap_dumper_t *pcap_dumper;
FlowsBuffer *flowBuffer;
QueueBuffer *queueBuffer;

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void initFlowBuffer(FlowsBuffer *fbs, unsigned int initSize);
void initQueue(QueueBuffer *q);
void enqueue(QueueBuffer *q, FlowInfo *flow);
FlowInfo *dequeue(QueueBuffer *q);
FlowInfo *queueSearch(QueueBuffer *q, struct in_addr ip_src, struct in_addr ip_dst, uint16_t src_port, uint16_t dst_port);

/**
 * TODO
 * ? Install zeek flowmeter
 */
void handle_sigint(){
    printf("packet captured : %d",packet_count);
    exit(0);
}

int main(int argc, char **argv)
{
    signal(SIGINT, handle_sigint);
    pcap_t *handle;
    flowBuffer = (FlowsBuffer *)malloc(sizeof(FlowsBuffer));
    queueBuffer = (QueueBuffer *)malloc(sizeof(QueueBuffer));
    initQueue(queueBuffer);
    if(flowBuffer == NULL){
        perror("error allocating memory for flow buffer");
    }
    initFlowBuffer(flowBuffer, 10);
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

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    // PROTOCOL TCP
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    if (ip_header->ip_p == IPPROTO_TCP)
    {
        packet_count++;
        tcp_handler((FlowsBuffer *)user_data, packet, pkthdr);
    }
    
}

void initFlowBuffer(FlowsBuffer *fbs, unsigned int initSize)
{
    fbs->flows = (FlowInfo *)malloc(sizeof(FlowInfo) * initSize);
    fbs->capacity = initSize;
    fbs->count = 0;
}

void initQueue(QueueBuffer *q)
{
    q->front = q->rear = NULL;
}

void enqueue(QueueBuffer *q, FlowInfo *flow)
{
    Node *newNode = (Node *)malloc(sizeof(Node));
    if (!newNode)
    {
        printf("Memory allocation failed\n");
        return;
    }
    newNode->flow = flow;
    newNode->next = NULL;

    if (q->rear == NULL)
    {
        q->front = q->rear = newNode;
        return;
    }

    q->rear->next = newNode;
    q->rear = newNode;
}

FlowInfo *dequeue(QueueBuffer *q)
{
    if (q->front == NULL)
    {
        printf("Queue is empty\n");
        return NULL;
    }

    Node *temp = q->front;
    FlowInfo *value = temp->flow;
    q->front = q->front->next;

    if (q->front == NULL)
    {
        q->rear = NULL;
    }

    free(temp);
    return value;
}

FlowInfo *queueSearch(QueueBuffer *q, struct in_addr ip_src, struct in_addr ip_dst, uint16_t src_port, uint16_t dst_port)
{
    Node *current = q->front;

    while (current != NULL)
    {
        if (current->flow->src_ip.s_addr == ip_src.s_addr &&
            current->flow->dst_ip.s_addr == ip_dst.s_addr &&
            current->flow->src_port == src_port &&
            current->flow->dst_port == dst_port)
        {
            return current->flow;
        }
        current = current->next;
    }
    return NULL; // If no match is found
}