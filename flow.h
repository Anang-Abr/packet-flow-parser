#ifndef FLOW_INFO_H
#define FLOW_INFO_H
#include <stdbool.h>

typedef struct
{
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int packet_count;
    char protocol;
    long *ts_sec;
    long *ts_msec;
    int fwd;
    int bwd;
    int fwd_tot;
    int bwd_tot;
    int fwd_hdr_min;
    int bwd_hdr_min;
    int fwd_hdr_max;
    int bwd_hdr_max; 
    int FIN_count;
    int SYN_count;
    int PSH_bwd_count;
    int PSH_fwd_count;
    int ACK_count;
    int URG_bwd_count;
    int URG_fwd_count;
    int ECE_count;
    int CWR_count;
    int RST_count;
    int fwd_payload_min;
    int fwd_payload_max;
    unsigned long fwd_payload_tot;
    int fwd_payload_std;
    int bwd_payload_min;
    int bwd_payload_max;
    unsigned long bwd_payload_tot;
    int bwd_payload_std;
    long *payloads_size;
    unsigned long capacity;
    bool hasFin;
    bool waitACK;
} FlowInfo;

typedef struct{
    FlowInfo *flows;
    unsigned int capacity;
    unsigned int count;
    FlowInfo *deleted;
} FlowsBuffer;

typedef struct Node{
    FlowInfo *flow;
    struct Node *next;
} Node;

typedef struct Queue{
    Node *front;
    Node *rear;
} QueueBuffer;


#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10
#define F_URG 0x20
#define F_ECE 0x40
#define F_CWR 0x80

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void initFlowBuffer(FlowsBuffer *fbs, unsigned int initSize);
void initQueue(QueueBuffer *q);
void enqueue(QueueBuffer *q, FlowInfo *flow);
FlowInfo *dequeue(QueueBuffer *q);
FlowInfo *queueSearch(QueueBuffer *q, struct in_addr ip_src, struct in_addr ip_dst, uint16_t src_port, uint16_t dst_port);

extern QueueBuffer *queueBuffer;

#endif