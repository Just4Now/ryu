''' A simple swtich module created by young713 '''

import struct
import time
from multiprocessing import Process, Queue
import math
import numpy as np

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48
MAX_SIZE_OF_NS_PACKET = 1500
IP_TCP = 6
POLLING_TIME = 300
MAX_ENTROPY_COUNT = 120

class MySimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MySimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_table = {}
        self.que = Queue()
        #实际值 预测值 
        self.src_ip_entropy = [[], []]
        self.dst_ip_entropy = [[], []]
        self.src_port_entropy = [[], []]
        self.dst_port_entropy = [[], []]
        self.bytes_per_entropy = [[], []]
        self.recv_ns_pkt = Process(target=self.parser_netstream_packet, args=self)
        self.detect_anomaly = Process(target=self.detect_tcp_syn_flood, args=self)
        self.recv_ns_pkt.start()
        self.detect_anomaly.start()
        #self.recv_ns_pkt.terminate()
        #self.detect_anomaly.terminate()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #install a table-miss flow entry into a connected switch
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        self.mac_table[dpid] = {}

        command = ofp.OFPFC_ADD
        priority = 0
        buffer_id = ofp.OFP_NO_BUFFER
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, 0)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]

        req = ofp_parser.OFPFlowMod(datapath, command=command, match=match, 
                                    priority=priority, buffer_id=buffer_id, 
                                    instructions=inst)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def switch_packetin_handler(self, ev):
        msg = ev.msg
        data = msg.data
        datapath = msg.datapath
        dpid = datapath.id
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        buffer_id = msg.buffer_id
        mac_table = self.mac_table

        #extract the src mac-address and the dst mac-address of the packet
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        #update the mac table
        mac_table[dpid][src] = in_port

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        #search the mac table
        if dst in mac_table[dpid]:
            out_port = mac_table[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD
        actions = [ofp_parser.OFPActionOutput(out_port, 0)]
        #send a flow-mod message
        if out_port != ofp.OFPP_FLOOD:
            command = ofp.OFPFC_ADD
            match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst)
            priority = 1
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            req = ofp_parser.OFPFlowMod(datapath, command=command, match=match,
                                        priority=priority, instructions=inst)
            datapath.send_msg(req)

        #send a packet-out message
        req = ofp_parser.OFPPacketOut(datapath, buffer_id, in_port,
                                      actions, data)
        datapath.send_msg(req)

    def detect_tcp_syn_flood(self):
        timestamp = time.time()
        src_ip = {}
        dst_ip = {}
        src_port = {}
        dst_port = {}
        bytes_per_pkt = {}
        flow_count = 0
        alpha = 0.1
        while True:
            nsdata = self.que.get(True)
            diff_time = timestamp - nsdata['timestamp']
            if diff_time > 0:
                flow_count = flow_count + 1
                check_if_exists(nsdata['src_ip'], src_ip)
                check_if_exists(nsdata['dst_ip'], dst_ip)
                check_if_exists(nsdata['src_port'], src_port)
                check_if_exists(nsdata['dst_port'], dst_port)
                check_if_exists(nsdata['bytes_per_pkt'], bytes_per_pkt)
            else:
                self.que.put(nsdata)
                break
        #calculate information entropy
        src_ip_entropy = cal_info_entropy(flow_count, src_ip)
        dst_ip_entropy = cal_info_entropy(flow_count, src_ip)
        src_port_entropy = cal_info_entropy(flow_count, src_ip)
        dst_port_entropy = cal_info_entropy(flow_count, src_ip)
        bytes_per_pkt_entropy = cal_info_entropy(flow_count, src_ip)

        #use exponential smoothing predicting model
        if self.src_ip_entropy[0]:
            self.src_ip_entropy[1].append(src_ip_entropy)
            self.dst_ip_entropy[1].append(dst_ip_entropy)
            self.src_port_entropy[1].append(src_port_entropy)
            self.dst_port_entropy[1].append(dst_port_entropy)
            self.bytes_per_entropy[1].append(bytes_per_entropy)
        else:
            #compare with the predict information entropy
            src_ip_std = np.std(self.src_ip_entropy[0], ddof=1)
            dst_ip_std = np.std(self.dst_ip_entropy[0], ddof=1)
            src_port_std = np.std(self.src_port_entropy[0], ddof=1)
            dst_port_std = np.std(self.dst_port_entropy[0], ddof=1)
            bytes_per_pkt_std = np.std(self.bytes_per_pkt_entropy[0], ddof=1)

            if abs(self.src_ip_entropy[1][-1] - src_ip_entropy) >= 3 * src_ip_std:
                if abs(self.dst_ip_entropy[1][-1] - dst_ip_entropy) >= 3 * dst_ip_std:
                    if abs(self.src_port_entropy[1][-1] - src_port_entropy) >= 3 * src_port_std:
                        if abs(self.dst_port_entropy[1][-1] - dst_port_entropy) >= 3 * dst_port_std:
                            if abs(self.bytes_per_entropy[1][-1] - bytes_per_entropy) >= 3 * bytes_per_pkt_std:
                                self.logger.info("Warining: the system may be under tcp syn flood attack!")

            self.src_ip_entropy[1].append(alpha * src_ip_entropy +
                                          (1 - alpha) * self.src_ip_entropy[1][-1])
            self.dst_ip_entropy[1].append(alpha * dst_ip_entropy +
                                          (1 - alpha) * self.dst_ip_entropy[1][-1])
            self.src_port_entropy[1].append(alpha * src_port_entropy +
                                            (1 - alpha) * self.src_port_entropy[1][-1])
            self.dst_port_entropy[1].append(alpha * dst_port_entropy +
                                            (1 - alpha) * self.dst_port_entropy[1][-1])
            self.bytes_per_pkt_entropy[1].append(alpha * bytes_per_pkt_entropy +
                                                 (1 - alpha) * self.bytes_per_pkt_entropy[1][-1])

        if(len(self.src_ip_entropy[0]) >= MAX_ENTROPY_COUNT):
            self.src_ip_entropy[0].pop(0)
            self.dst_ip_entropy[0].pop(0)
            self.src_port_entropy[0].pop(0)
            self.dst_port_entropy[0].pop(0)
            self.bytes_per_pkt_entropy[1].pop(0)
            self.src_ip_entropy[1].pop(0)
            self.dst_ip_entropy[1].pop(0)
            self.src_port_entropy[1].pop(0)
            self.dst_port_entropy[1].pop(0)
            self.bytes_per_pkt_entropy[1].pop(0)

        self.src_ip_entropy[0].append(src_ip_entropy)
        self.dst_ip_entropy[0].append(dst_ip_entropy)
        self.src_port_entropy[0].append(src_port_entropy)
        self.dst_port_entropy[0].append(dst_port_entropy)
        self.bytes_per_pkt_entropy[0].append(bytes_per_pkt_entropy)

        time.sleep(POLLING_TIME)

    def parser_netstream_packet(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 6666))
        while True:
            buf, addr = sock.recvfrom(MAX_SIZE_OF_NS_PACKET)

            (version, count) = struct.unpack('!HH', buf[0:4])
            if version != 5:
                continue
            # It's pretty unlikely you'll ever see more then 1000 records in a 1500 byte UDP packet
            if count <= 0 or count > 30:
                continue

            #uptime = socket.ntohl(struct.unpack('I',buf[4:8])[0])
            #epochseconds = socket.ntohl(struct.unpack('I',buf[8:12])[0])

            for i in range(0, count):
                try:
                    base = SIZE_OF_HEADER + (i * SIZE_OF_RECORD)

                    nsdata = {}

                    nsdata['protocol'] = struct.unpack('B', buf[base+38])
                    if nsdata['protocol'] != IP_TCP:
                        pass

                    nsdata['src_ip'] = struct.unpack('!I', buf[base+0:base+4])
                    nsdata['dst_ip'] = struct.unpack('!I', buf[base+4:base+8])

                    data = struct.unpack('!IIIIHH', buf[base+16:base+36])
                    nsdata['bytes_per_pkt'] = data[1] // data[0]
                    nsdata['src_port'] = data[4]
                    nsdata['dst_port'] = data[5]
                    nsdata['timestamp'] = time.time()
                    self.que.put(nsdata)
                except Exception:
                    continue

def check_if_exists(key, net_dict):
    if key in net_dict:
        net_dict[key] = net_dict[key] + 1
    else:
        net_dict[key] = 1

def cal_info_entropy(num, net_dict):
    info_entropy = 0.0
    for n in net_dict.valuse():
        info_entropy = info_entropy + n / num * math.log(2, n / num)
    return -1 * info_entropy

