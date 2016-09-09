# pcap-analyser
A minimal pcap analyzer for tcp connections.

The pcap file was parsed using dpkt python library. The library was used solely for extracting the time stamp and the raw packet bytes.  

From the packet bytes, I used manual bit manipulations and parsing to extract the relevant information. I assumed the Ethernet packets were of Ethernet 2 type. The 13th and 14th byte indicates the upper level protocol. If the type is non IP, I ignore the packet.  

In IP, I use the header format to manually extract the upper layer type, length, src and dst etc. Using the protocol type in IP, I ignore the non-tcp packets.  

Similarly, using the TCP packet format, I extracted the relevant seq number, ack number, pay load data etc.   

I maintain flow state for each TCP flow in the form of a dictionary in Python. A flow is defined by (src ip, src port, dst ip, dst port). For each flow, I maintain the relevant met data needed such as the seq number, last ack number, congestion window, useful bytes sent, all bytes sent etc.  

As parsing through the packets, on getting a SYN from a client, we first setup the flow in stage 1, record the time and initialize the flow state with sensible default values. With the 3-way handshake, it moves from stage 1 to stage 3.  

At this stage, we also compute the initial congestion window. This is done by first parsing the TCP options to get the sender(client) MSS. Based on the MSS value, as defined in RFC 5681, we then calculate the initial congestion window as a multiple of MSS.  

On receiving a packet for an already setup flow, we perform the necessary updates to out flow state information such as bytes sent, new sequence number etc.  
In this way, we are able to maintain all the required information needed to answer the questions.  

Once we receive a fin for an already setup flow, we now record the end time and perform the necessary computations to output the result.  

Throughput calculation includes all the bytes sent at the TCP level (including protocol over head + data + re transmissions + duplicate acks) from connection setup till the FIN packet from the client.  
Goodput calculation includes all the bytes sent at the TCP level (including protocol over head + data ) minus the re-transmissions and duplicate acks, from connection setup till the FIN packet from the client.  
Total time considered is the time from after connection setup, till the client issues a FIN packet.  
Average RTT is calculated based on successful RTT samples. I used Karns algorithm for RTT sampling. According to it, I ignore considering RTT's for duplicate ack or retransmitted acks. I am also not considering empty acks sent from client side for RTT since empty acks would not need a response from the server.  
