#include <stdio.h>
#include <stdbool.h>
#include <omp.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include "utils/cJSON.h"
#include "utils/cJSON.c"
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include "flow.h"
#include "./handler/handler.h"
#include "main.h"

#define MAX_FLOWS 10
#define MAX_PACKETS 30
#define FLOW_TIMEOUT 5

unsigned int flow_count = 0;
unsigned long packet_count = 0;
unsigned long packet_received = 0;
unsigned long packet_processed = 0;
pcap_dumper_t *pcap_dumper;
FlowsBuffer *flowBuffer;
QueueBuffer *queueBuffer;
FILE *fptr;
int count = 0;

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void initFlowBuffer(FlowsBuffer *fbs, unsigned int initSize);
void initQueue(QueueBuffer *q);
void enqueue(QueueBuffer *q, FlowInfo *flow);
FlowInfo *dequeue(QueueBuffer *q);
FlowInfo *queueSearch(QueueBuffer *q, struct in_addr ip_src, struct in_addr ip_dst, uint16_t src_port, uint16_t dst_port);
void freeQueue(QueueBuffer *q);
void handle_sigint();
void timeoutCheck(FlowsBuffer *flowBuffer);

unsigned int flow_buffer_count = 0;
unsigned int found_in_queue = 0;


void print_usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s -i <interface> \n", prog_name);
    fprintf(stderr, "  -i, --interface <interface>  : Specify the network interface\n");
    exit(EXIT_FAILURE);
}

int check_interface(const char *interface)
{
    return if_nametoindex(interface) != 0;
}

int main(int argc, char *argv[])
{
    
    int opt;
    char *interface = NULL;
    char *export_file = NULL;
    while((opt = getopt(argc, argv, "i:e:h")) != -1){
        switch(opt){
            case 'i':
                interface = optarg;
                break;
            case 'e':
                export_file = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
            default:
                print_usage(argv[0]);

        }
    }

    if (interface == NULL)
    {
        perror("network interface should be specified\n");
        exit(EXIT_FAILURE);
    }
    if (!check_interface(interface))
    {
        perror("the specified interface not found\n");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_sigint);
    flowBuffer = (FlowsBuffer *)malloc(sizeof(FlowsBuffer));
    queueBuffer = (QueueBuffer *)malloc(sizeof(QueueBuffer));
    initQueue(queueBuffer);
    pcap_t *handle;
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
    if(export_file != NULL){
    fptr = fopen(export_file, "a");
    if (fptr == NULL)
    {
        perror("failed to open the log");
        exit(EXIT_FAILURE);
    }
    }
    #pragma omp parallel sections
    {
        #pragma omp section
        {
            while (1)
            {
                timeoutCheck(flowBuffer);
                sleep(1);
            }
        }

        #pragma omp section
        {
            handle = pcap_open_live(interface, BUFSIZ * 2, 1, 1000, errbuf);
            if (handle == NULL)
            {
                printf("Error opening device: %s\n", errbuf);
                exit(EXIT_SUCCESS);
            }
            pcap_loop(handle, 0, packet_handler, (unsigned char *)flowBuffer);
            pcap_close(handle);
            fclose;
        }
    }
    return 0;
}

void timeoutCheck(FlowsBuffer *flowBuffer)
{
    time_t currentTime = time(NULL);
    for (int i = 0; i < flowBuffer->count; i++)
    {
        double timeDiff = difftime(currentTime, flowBuffer->flows[i].last_updated);
        if (timeDiff > FLOW_TIMEOUT && !flowBuffer->flows[i].is_exported)
        {
            // flow are exported by timeout
            printFlowInfo(&flowBuffer->flows[i]);
        }
    }
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

void enqueue(QueueBuffer *q, FlowInfo *flow)
{
    Node *newNode = (Node *)malloc(sizeof(Node));
    if (!newNode)
    {
        printf("Memory allocation failed\n");
        return;
    }
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

FlowInfo *dequeue(QueueBuffer *q)
{
    if (q->front == NULL)
    {
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

FlowInfo *queueSearch(QueueBuffer *q, struct in_addr ip_src, struct in_addr ip_dst, uint16_t src_port, uint16_t dst_port)
{
    Node *current = q->front;

    while (current != NULL)
    {
        if ((current->flow->src_ip.s_addr == ip_src.s_addr &&
             current->flow->dst_ip.s_addr == ip_dst.s_addr &&
             current->flow->src_port == src_port &&
             current->flow->dst_port == dst_port) ||
            current->flow->src_ip.s_addr == ip_dst.s_addr &&
                current->flow->dst_ip.s_addr == ip_src.s_addr &&
                current->flow->src_port == dst_port &&
                current->flow->dst_port == src_port)
        {
            return current->flow;
        }
        current = current->next;
    }
    return NULL;
}

void freeQueue(QueueBuffer *q)
{
    Node *current = q->front;
    Node *next;

    while (current != NULL)
    {
        next = current->next;
        free(current);
        current = next;
    }
    q->front = q->rear = NULL;
    free(q);
}

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
    printf("flows count: %d\n", count);


    // cleanup
    freeQueue(queueBuffer);
    free(flowBuffer->flows);
    free(flowBuffer);
    if(fptr != NULL){
        if (fclose(fptr) != 0)
        {
            perror("failed to close the log");
        }
    }
    exit(EXIT_SUCCESS);
}