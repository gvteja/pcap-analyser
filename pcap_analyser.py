import dpkt

ETH_IP_TYPE = 0x800

TCP_PROTO = 0x06

SYN_MASK = 0x02
FIN_MASK = 0x01
ACK_MASK = 0x10
RST_MASK = 0x04

NO_OP_OPT = 0x01
END_OPT = 0x00
MSS_OPT = 0x02


# the key is (src ip, dst ip, src port, dst port)
# val is (state, last_seq_num, total_bytes_sent, total_useful_sent, initial_seq_num, initial_congestion_window, initial_ts, seq_ts, rtts, cwnd, last_ack_by_client, last_ack_by_serv, congestion_state)
# seq_ts is a map of {expected_ack_num:ts of the sq}
tcp_flows = {}

rtt_cwnd = []

smss = 0

num_rtt = 1

def bit_mask(num_one_bits, start_pos):

    val = 1 << num_one_bits
    val = val - 1

    num_zero_bits = start_pos - num_one_bits
    val = val << num_zero_bits

    return val


def b_to_int(byte_arr):
    val = byte_arr[0]
    for byte in byte_arr[1:]:
        # network byte order is big endian
        val = (val << 8) + byte

    return val


def get_iw_mss(tcp_options):

    while tcp_options:
        if tcp_options[0] == END_OPT:
            break
        elif tcp_options[0] == NO_OP_OPT:
            tcp_options = tcp_options[1:]
        elif tcp_options[0] == MSS_OPT:
            mss_len = tcp_options[1] - 2
            mss = b_to_int(tcp_options[2:2 + mss_len])

            # as per RFC 5681
            if mss > 2190:
                iw = 2 * mss
            elif mss > 1085:
                iw = 3 * mss
            else:
                iw = 4 * mss
            
            return iw, mss


def parse_pkt(ts, pkt):

    # assuming its an ethernet 2 pkt
    # the eth type is 13 and 14 byte
    eth_type = b_to_int(pkt[12:14])
    if eth_type != ETH_IP_TYPE:
        # its not an IP pkt. Ignore
        #print 'ignoring non ip pkt'
        return

    # get the ip pkt now
    # note: this includes the extra eth crc at the end
    # but for our purpose, we will never touch that
    ip_pkt = pkt[14:]

    # ip version is the 1st 4 bit of the 1st byte
    ip_version = ip_pkt[0] >> 4

    if ip_version != 4:
        # ignore non ipv4 pkts
        #print 'ignoring non ipv4 pkt'
        return
    
    # the upper layer protocol is the 10th byte
    transport_proto = ip_pkt[9]

    if transport_proto != TCP_PROTO:
        # ignore non tcp pkts
        #print 'ignoring non tcp pkt'
        return

    ip_src = b_to_int(ip_pkt[12:16])
    ip_dst = b_to_int(ip_pkt[16:20])

    ip_src_str = '.'.join([str(num) for num in ip_pkt[12:16]])
    ip_dst_str = '.'.join([str(num) for num in ip_pkt[16:20]])

    ip_header_size = (ip_pkt[0] & bit_mask(4, 4)) * 4
    ip_total_size = b_to_int(ip_pkt[2:4])

    tcp_pkt = ip_pkt[ip_header_size : ip_total_size]

    tcp_src = b_to_int(tcp_pkt[:2])
    tcp_dst = b_to_int(tcp_pkt[2:4])

    #print ip_src_str, tcp_src, '--TO--', ip_dst_str, tcp_dst

    seq_num = b_to_int(tcp_pkt[4:8])
    ack_num = b_to_int(tcp_pkt[8:12])

    window_size = b_to_int(tcp_pkt[14:16])

    #print seq_num, ack_num, window_size

    # the 13th byte has all the flags
    tcp_flags = tcp_pkt[13]

    syn_set = tcp_flags & SYN_MASK
    ack_set = tcp_flags & ACK_MASK
    fin_set = tcp_flags & FIN_MASK
    rst_set = tcp_flags & RST_MASK

    tcp_pkt_size = len(tcp_pkt)
    
    # tcp header size is first 4 bits of 13th byte
    tcp_header_size = (tcp_pkt[12] >> 4) * 4
    data_len = tcp_pkt_size - tcp_header_size

    if syn_set and not ack_set:
        #print '----------------------new flow stage 1----------------------'
        #print ts, (ip_src_str, tcp_src, ip_dst_str, tcp_dst)

        tcp_header_size = (tcp_pkt[12] >> 4) * 4
        tcp_options = tcp_pkt[20:tcp_header_size]

        iw, mss = get_iw_mss(tcp_options)

        seq_ts = {}
        rtts = []
        tcp_flows[(ip_src, tcp_src, ip_dst, tcp_dst)] = (1, seq_num, 0, 0, seq_num, iw, ts, seq_ts, rtts, iw, 0, 0, 1)

        global smss
        smss = mss

    elif rst_set:
        # discard the flow
        if (ip_src, tcp_src, ip_dst, tcp_dst) in tcp_flows:
            tcp_flows.pop((ip_src, tcp_src, ip_dst, tcp_dst))
    elif (ip_src, tcp_src, ip_dst, tcp_dst) in tcp_flows:
        # client side flow pkt

        (state, last_seq_num, total_bytes_sent, total_useful_sent, initial_seq_num, initial_window_size, initial_ts, seq_ts, rtts, cwnd, last_ack_by_client, last_ack_by_serv, congestion_state) = tcp_flows[(ip_src, tcp_src, ip_dst, tcp_dst)] 
        if fin_set:
            #print '----------------------flow closed----------------------'
            #print ts, (ip_src_str, tcp_src, ip_dst_str, tcp_dst)

            # print seq_num, initial_seq_num, tcp_pkt_size, tcp_header_size, data_len
            total_bytes_sent += tcp_pkt_size
            total_useful_sent += tcp_pkt_size
            total_time = ts - initial_ts

            print '\nStats for flow:', ip_src_str + ':' + str(tcp_src), '-->', ip_dst_str + ':' + str(tcp_dst)
            print 'Total time in sec:', total_time
            print 'Total bytes sent:', total_bytes_sent
            print 'Useful bytes sent:', total_useful_sent
            print 'Throughput in bytes/sec:', total_bytes_sent/total_time
            print 'Goodput in bytes/sec:', total_useful_sent/total_time
            print 'Initial congestion window in bytes:', initial_window_size
            print 'Avg RTT in millisec:', sum(rtts) / len(rtts)

            return

        elif ack_set and state == 2:
            # we just finished establishing connection
            state = 3
            # start the connection time from now
            initial_ts = ts
            last_ack_by_client = ack_num
            #print '----------------------new flow stage 3----------------------'
            #print ts, (ip_src_str, tcp_src, ip_dst_str, tcp_dst)
        else:
            # update bytes sent for calculating througput
            # these bytes include protocol header and retransmissions

            #print total_bytes_sent, total_useful_sent

            total_bytes_sent += tcp_pkt_size

            if (seq_num <= last_seq_num) and data_len:
                print 'retransmission of pkt:', (ip_src_str, tcp_src, ip_dst_str, tcp_dst), data_len, seq_num, last_seq_num
                if expected_ack in se:
                    seq_ts.pop(expected_ack)
            elif ack_num <= last_ack_by_client and not data_len:
                print 'duplicate ack:', (ip_src_str, tcp_src, ip_dst_str, tcp_dst), data_len, ack_num, last_ack_by_client
            else:
                # we consider even empty non duplicate acks are useful bytes
                if ack_num > last_ack_by_client:
                    last_ack_by_client = ack_num
                total_useful_sent += tcp_pkt_size
                if  data_len:
                    last_seq_num = seq_num
                    expected_ack = seq_num + data_len
                    seq_ts[expected_ack] = ts


        tcp_flows[(ip_src, tcp_src, ip_dst, tcp_dst)] = (state, last_seq_num, total_bytes_sent, total_useful_sent, initial_seq_num, initial_window_size, initial_ts, seq_ts, rtts, cwnd, last_ack_by_client, last_ack_by_serv, congestion_state)

    elif (ip_dst, tcp_dst, ip_src, tcp_src) in tcp_flows:
        # packet from server side

        (state, last_seq_num, total_bytes_sent, total_useful_sent, initial_seq_num, initial_window_size, initial_ts, seq_ts, rtts, cwnd, last_ack_by_client, last_ack_by_serv, congestion_state) = tcp_flows[(ip_dst, tcp_dst, ip_src, tcp_src)]

        if syn_set and ack_set:
            # it must be in state 1
            # update state to 2
            state = 2

            tcp_header_size = (tcp_pkt[12] >> 4) * 4
            tcp_options = tcp_pkt[20:tcp_header_size]
            
            initial_window_size, mss = get_iw_mss(tcp_options)

            last_ack_by_serv = ack_num

            #print '----------------------new flow stage 2----------------------'
            #print ts, (ip_src_str, tcp_src, ip_dst_str, tcp_dst)
        else:

            if ack_num > last_ack_by_serv:
                last_ack_by_serv = ack_num
                #print '--------------------------', num_rtt, '--------------------------'

            # update rtt
            try:
                client_seq_ts = seq_ts.pop(ack_num)
                rtt = (ts * 1000) - (client_seq_ts * 1000)
                # print 'popped for ack', ack_num
                #print "{0:.6f}".format(client_seq_ts), "{0:.6f}".format(ts), rtt
                rtts.append(rtt)

                global num_rtt
                rtt_cwnd.append((num_rtt, cwnd))

                # update cwnd depnding on current congestion state
                # every sccessful ack, upd cwnd by 1 mss
                if congestion_state == 1:
                    # in slow start phase
                    cwnd += smss


                
                num_rtt += 1
                print '--------------------------', num_rtt, '--------------------------'
                if num_rtt == 20:
                    return
            except:
                #print 'ignoring duplicate ack'
                #print state, seq_num, ack_num, (ip_src, tcp_src, ip_dst, tcp_dst)
                pass
                

        tcp_flows[(ip_dst, tcp_dst, ip_src, tcp_src)] = (state, last_seq_num, total_bytes_sent, total_useful_sent, initial_seq_num, initial_window_size, initial_ts, seq_ts, rtts, cwnd, last_ack_by_client, last_ack_by_serv, congestion_state)



def parse_pcap_file(file_name):

    print '\n\nAnalyzing tcp packets in pcap file:', file_name
    print '-----------------------------------------------------------'

    # reset the tcp flows
    global tcp_flows
    tcp_flows = {}

    pacp_file = open(file_name)
    pcap = dpkt.pcap.Reader(pacp_file)

    for ts, pkt in pcap:
        pkt = bytearray(pkt)
        parse_pkt(ts, pkt)

    print rtt_cwnd

    print '----------------'
    print 'Parsed', len(pcap.readpkts()), 'packets in pcap file:', file_name

#parse_pcap_file('HTTP_SampleA.pcap')
#parse_pcap_file('HTTP_SampleB.pcap')
parse_pcap_file('HTTP_Sample_Big_Packet.pcap')