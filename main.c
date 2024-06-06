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
unsigned long packet_count = 0;
unsigned long packet_received = 0;
unsigned long packet_processed = 0;
char protocol = 'O';
unsigned int tcp_flow = 0;
unsigned int udp_flow = 0;
pcap_dumper_t *pcap_dumper;
FlowsBuffer *flowBuffer;
QueueBuffer *queueBuffer;
FILE *fptr;

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void initFlowBuffer(FlowsBuffer *fbs, unsigned int initSize);
void initQueue(QueueBuffer *q);
void enqueue(QueueBuffer *q, FlowInfo *flow);
FlowInfo *dequeue(QueueBuffer *q);
FlowInfo *queueSearch(QueueBuffer *q, struct in_addr ip_src, struct in_addr ip_dst, uint16_t src_port, uint16_t dst_port);
void freeQueue(QueueBuffer *q);

unsigned int flow_buffer_count = 0;
unsigned int found_in_queue = 0;

/**
 * TODO
 * add params options to select network interface, export file name, and mode(optional)
 */

/**
 * Handle Signal Interupt, flush all the flows stored in the flow buffer
 */
void handle_sigint()
{
    for (int i = 0; i < flowBuffer->count; i++)
    {
        // checking if the flow already in the queueBuffer
        FlowInfo *is_queued = queueSearch(queueBuffer, flowBuffer->flows[i].src_ip, flowBuffer->flows[i].dst_ip, flowBuffer->flows[i].src_port, flowBuffer->flows[i].dst_port);

        if (is_queued != NULL)
            found_in_queue++;
        // if flow isn't yet stored in the queue buffer, export the flow
        else if (is_queued == NULL)
            printFlowInfo(&flowBuffer->flows[i]);

        // free the memory for the dynamic array
        if (flowBuffer->flows[i].payloads_size != NULL)
        {
            free(flowBuffer->flows[i].payloads_size);
        }
        if (flowBuffer->flows[i].ts_msec != NULL)
        {
            free(flowBuffer->flows[i].ts_msec);
        }
        if (flowBuffer->flows[i].ts_sec != NULL)
        {
            free(flowBuffer->flows[i].ts_sec);
        }
        flow_buffer_count++;
    }

    // printing captured count
    printf("packet received(without filter) : %ld\n", packet_received);
    printf("packet count(tcp filtered): %ld\n", packet_count);
    printf("packet processed(exported): %ld\n", packet_processed);
    printf("packet in queue : %d\n", queueBuffer->count);
    printf("packet in buffer: %d\n", flow_buffer_count);

    // cleanup
    freeQueue(queueBuffer);
    free(flowBuffer->flows);
    free(flowBuffer);
    if (fclose(fptr) != 0)
    {
        perror("failed to close the log");
    }
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    signal(SIGINT, handle_sigint);
    pcap_t *handle;
    flowBuffer = (FlowsBuffer *)malloc(sizeof(FlowsBuffer));
    queueBuffer = (QueueBuffer *)malloc(sizeof(QueueBuffer));
    initQueue(queueBuffer);
    if (flowBuffer == NULL)
    {
        perror("error allocating memory for flow buffer");
    }
    if (queueBuffer == NULL)
    {
        perror("error allocating memory for flow buffer");
    }
    initFlowBuffer(flowBuffer, 10);
    char errbuf[PCAP_ERRBUF_SIZE];
    fptr = fopen("./captured_packets/flow.json", "a");
    if (fptr == NULL)
    {
        perror("failed to open the log");
        exit(EXIT_FAILURE);
    }
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

// handling the packet listener
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    // PROTOCOL TCP
    packet_received++;
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
    if (ip_header->ip_p == IPPROTO_TCP)
    {
        tcp_handler((FlowsBuffer *)user_data, packet, pkthdr);
        packet_count++;
    }
}

void initFlowBuffer(FlowsBuffer *fbs, unsigned int initSize)
{
    fbs->flows = (FlowInfo *)malloc(sizeof(FlowInfo) * initSize);
    if (fbs->flows == NULL)
    {
        free(fbs);
        perror("error allocating memory\n");
    }
    fbs->capacity = initSize;
    fbs->count = 0;
}

void initQueue(QueueBuffer *q)
{
    q->front = q->rear = NULL;
    q->count = 0;
}

// push into queue
void enqueue(QueueBuffer *q, FlowInfo *flow)
{
    Node *newNode = (Node *)malloc(sizeof(Node));
    if (!newNode)
    {
        printf("Memory allocation failed\n");
        return;
    }
    // printf("enqueue port: %d\n", ntohs(flow->src_port));
    reset_flow(flow);
    newNode->flow = flow;
    newNode->next = NULL;
    q->count++;

    if (q->rear == NULL)
    {
        q->front = q->rear = newNode;
        return;
    }

    q->rear->next = newNode;
    q->rear = newNode;
}

// poping the queue
FlowInfo *dequeue(QueueBuffer *q)
{
    if (q->front == NULL)
    {
        // printf("Queue is empty\n");
        return NULL;
    }

    Node *temp = q->front;
    FlowInfo *value = temp->flow;
    q->front = q->front->next;
    q->count--;

    if (q->front == NULL)
    {
        q->rear = NULL;
    }

    free(temp);
    return value;
}

// search flow in the queue
FlowInfo *queueSearch(QueueBuffer *q, struct in_addr ip_src, struct in_addr ip_dst, uint16_t src_port, uint16_t dst_port)
{
    Node *current = q->front;

    while (current != NULL)
    {
        // printf("\n%d == %d\n", ntohs(current->flow->src_port), ntohs(src_port));
        if (current->flow->src_ip.s_addr == ip_src.s_addr &&
            current->flow->dst_ip.s_addr == ip_dst.s_addr &&
            current->flow->src_port == src_port &&
            current->flow->dst_port == dst_port)
        {
            // printf("found");
            return current->flow;
        }
        current = current->next;
    }
    return NULL; // If no match is found
}

// clean up memory allocation in the queue
void freeQueue(QueueBuffer *q)
{
    Node *current = q->front;
    Node *next;

    while (current != NULL)
    {
        next = current->next;
        // free(current->flow); // Free the FlowInfo structure
        free(current); // Free the node
        current = next;
    }

    // Finally, reset the queue pointers
    q->front = q->rear = NULL;
    free(q);
}