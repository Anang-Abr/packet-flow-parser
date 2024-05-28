#ifndef FLOW_INFO_H
#define FLOW_INFO_H

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
    // time_t ts_last;
    // time_t tms_start;
    // time_t tms_last;
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
    int fwd_pkts_payload_min;
    int fwd_pkts_payload_max;
    int fwd_pkts_payload_tot;
    int fwd_pkts_payload_std;
    int bwd_pkts_payload_min;
    int bwd_pkts_payload_max;
    int bwd_pkts_payload_tot;
    int bwd_pkts_payload_std;
    // int flow_pkts_payload_min;
    // int flow_pkts_payload_max;
    // int flow_pkts_payload_tot;
    // int flow_pkts_payload_std;
    // int pkt_array[50];
} FlowInfo;

typedef struct{
    FlowInfo *flows;
    unsigned int capacity;
    unsigned int count;
} FlowsBuffer;

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10
#define F_URG 0x20
#define F_ECE 0x40
#define F_CWR 0x80

#endif