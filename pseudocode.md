```
STRUCT FlowInfo
    STRING src_ip
    STRING dst_ip
    INT sport
    INT dport

DEFINE queueBuffer AS QUEUE OF FlowInfo
DEFINE flowBuffer AS ARRAY OF FlowInfo
```


```
FUNCTION initFlowBuffer(fb, initSize)
    ALLOCATE memory for fb with size initSize
    INITIALIZE fb.capacity to initSize
    INITIALIZE fb.count to 0

FUNCTION tcp_generate_new_flow(packet, pkthdr) RETURNS FlowInfo
    INITIALIZE newFlow AS FlowInfo
    SET newFlow fields based on packet and pkthdr data
    RETURN newFlow
```

```
FUNCTION enqueue(queueBuffer, flow)
    ADD flow to queueBuffer

FUNCTION dequeue(queueBuffer) RETURNS FlowInfo
    IF queueBuffer IS NOT EMPTY
        REMOVE and RETURN first element from queueBuffer
    ELSE
        RETURN NULL

FUNCTION searchQueue(queueBuffer, criteria) RETURNS FlowInfo
    FOR each flow IN queueBuffer
        IF flow matches criteria
            RETURN flow
    RETURN NULL
```

```
FUNCTION printFlowInfo(flow)
    IF flow IS NULL
        PRINT "FlowInfo is NULL"
        RETURN
    PRINT flow.src_ip, flow.dst_ip, flow.sport, flow.dport, flow.last_seen

FUNCTION tcp_update_flow(flow, tcp_header)
    IF flow IS NULL OR tcp_header IS NULL
        PRINT "Invalid parameters"
        RETURN
    SET flow.last_seen to current time
    // Update other fields as necessary

FUNCTION tcp_handler(packet, pkthdr)
    DEFINE ip_header, tcp_header
    EXTRACT ip_header and tcp_header from packet

    DEFINE found_flow AS FlowInfo
    SET found_flow TO find_flow_index(fb, ip_header.src, ip_header.dst, tcp_header.sport, tcp_header.dport)

    IF found_flow IS NULL
        INCREMENT flow_count
        SET found_flow TO dequeue(queueBuffer)
        IF found_flow IS NULL
            SET found_flow TO tcp_generate_new_flow(packet, pkthdr)
            ADD found_flow TO fb
            INCREMENT fb.count
        ELSE
            REINITIALIZE found_flow WITH new flow data FROM tcp_generate_new_flow(packet, pkthdr)

    CALL tcp_update_flow(found_flow, tcp_header)
```

```
FUNCTION main
    INITIALIZE flowBuffer AS FlowsBuffer
    CALL initFlowBuffer(flowBuffer, 10)

    // Set up libpcap to capture packets
    SET handle TO pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)
    IF handle IS NULL
        PRINT "Could not open device"
        RETURN 2

    // Loop to capture packets
    CALL pcap_loop(handle, 0, packet_handler, NULL)

FUNCTION packet_handler(userdata, pkthdr, packet)
    CALL tcp_handler(packet, pkthdr)

    // Other necessary logic
    IF end_of_tcp_connection_detected(packet)
        PRINT "End of TCP connection"
        CALL enqueue(queueBuffer, current_flow)

```