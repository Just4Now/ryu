# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import struct
import time
import math
import socket
from multiprocessing import Process, Queue
import numpy as np

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48
MAX_SIZE_OF_NS_PACKET = 1500
IP_TCP = 6
POLLING_TIME = 60
MAX_ENTROPY_COUNT = 120
ACTUAL = 0
PREDICT = 1

class NetStreamAnalyzer13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.info_entropy = {}
        self.que = Queue()
        self.recv_ns_pkt = Process(target=self.parser_netstream_packet)
        self.detect_anomaly = Process(target=self.detect_tcp_syn_flood)
        self.recv_ns_pkt.start()
        self.detect_anomaly.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def detect_tcp_syn_flood(self):
        detect_flag = False
        for ip_addr in self.info_entropy:
            if self.info_entropy[ip_addr]['src_ip'][ACTUAL]:
                detect_flag = True
                break
        if not detect_flag and self.que.empty():
            time.sleep(POLLING_TIME)
        timestamp = int(time.time())
        netstream_record = {}
        alpha = 0.1

        while not self.que.empty():
            #self.logger.info("que length: %s", self.que.qsize())
            nsdata = self.que.get(True)
            self.logger.info('detect_tcp_syn_flood nsdata: %s', nsdata)
            diff_time = timestamp - nsdata['timestamp']
            if diff_time > 0:
                system_ip_addr = nsdata['system_ip']
                if not system_ip_addr in netstream_record:
                    netstream_record[system_ip_addr] = {'src_ip':{}, 'dst_ip':{},
                                                        'src_port': {}, 'dst_port':{},
                                                        'bytes_per_pkt':{}, 'flow_count':0}
                check_if_exists(nsdata['src_ip'],
                                netstream_record[system_ip_addr]['src_ip'])
                check_if_exists(nsdata['dst_ip'],
                                netstream_record[system_ip_addr]['dst_ip'])
                check_if_exists(nsdata['src_port'],
                                netstream_record[system_ip_addr]['src_port'])
                check_if_exists(nsdata['dst_port'],
                                netstream_record[system_ip_addr]['dst_port'])
                check_if_exists(nsdata['bytes_per_pkt'],
                                netstream_record[system_ip_addr]['bytes_per_pkt'])
                self.info_entropy[system_ip_addr]['flow_count'] = \
                                netstream_record[system_ip_addr]['flow_count'] + 1
            else:
                self.que.put(nsdata)
                break
        #calculate information entropy for each netstream system
        for ip_addr, ns_record in netstream_record.items():
            flow_count = ns_record['flow_count']

            if flow_count == 0 and not self.info_entropy[ip_addr]['src_ip'][ACTUAL]:
                continue

            curr_src_ip_entropy = cal_info_entropy(flow_count, ns_record['src_ip'])
            curr_dst_ip_entropy = cal_info_entropy(flow_count, ns_record['dst_ip'])
            curr_src_port_entropy = cal_info_entropy(flow_count, ns_record['src_port'])
            curr_dst_port_entropy = cal_info_entropy(flow_count, ns_record['dst_port'])
            curr_bytes_per_pkt_entropy = cal_info_entropy(flow_count, ns_record['bytes_per_pkt'])

            #use exponential smoothing predicting model
            if not self.info_entropy[ip_addr]['src_ip'][ACTUAL]:
                self.info_entropy[ip_addr]['src_ip'][PREDICT].append(curr_src_ip_entropy)
                self.info_entropy[ip_addr]['dst_ip'][PREDICT].append(curr_dst_ip_entropy)
                self.info_entropy[ip_addr]['src_port'][PREDICT].append(curr_src_port_entropy)
                self.info_entropy[ip_addr]['dst_port'][PREDICT].append(curr_dst_port_entropy)
                self.info_entropy[ip_addr]['bytes_per_pkt'][PREDICT].append(curr_bytes_per_pkt_entropy)
            else:
                #compare with the predict information entropy
                src_ip_std = np.std(self.info_entropy[ip_addr]['src_ip'][ACTUAL], ddof=1)
                dst_ip_std = np.std(self.info_entropy[ip_addr]['dst_ip'][ACTUAL], ddof=1)
                src_port_std = np.std(self.info_entropy[ip_addr]['src_port'][ACTUAL], ddof=1)
                dst_port_std = np.std(self.info_entropy[ip_addr]['dst_port'][ACTUAL], ddof=1)
                bytes_per_pkt_std = np.std(self.info_entropy[ip_addr]['bytes_per_pkt'][ACTUAL], ddof=1)

                if abs(self.info_entropy[ip_addr]['src_ip'][PREDICT][-1] - curr_src_ip_entropy) >= 3 * src_ip_std and \
                   abs(self.info_entropy[ip_addr]['dst_ip'][PREDICT][-1] - curr_dst_ip_entropy) >= 3 * dst_ip_std and \
                   abs(self.info_entropy[ip_addr]['src_port'][PREDICT][-1] - curr_src_port_entropy) >= 3 * src_port_std and \
                   abs(self.info_entropy[ip_addr]['dst_port'][PREDICT][-1] - curr_dst_port_entropy) >= 3 * dst_port_std and \
                   abs(self.info_entropy[ip_addr]['bytes_per_pkt'][PREDICT][-1] - curr_bytes_per_pkt_entropy) >= 3 * bytes_per_pkt_std:
                    self.logger.info('Waring: the system(%s) may be under tcp syn flood attack!', ip_addr)

                self.info_entropy[ip_addr]['src_ip'][PREDICT].append(alpha * curr_src_ip_entropy +
                                                                     (1 - alpha) * self.info_entropy[ip_addr]['src_ip'][PREDICT][-1])
                self.info_entropy[ip_addr]['dst_ip'][PREDICT].append(alpha * curr_dst_ip_entropy +
                                                                     (1 - alpha) * self.info_entropy[ip_addr]['dst_ip'][PREDICT][-1])
                self.info_entropy[ip_addr]['src_port'][PREDICT].append(alpha * curr_src_port_entropy +
                                                                     (1 - alpha) * self.info_entropy[ip_addr]['src_port'][PREDICT][-1])
                self.info_entropy[ip_addr]['dst_port'][PREDICT].append(alpha * curr_dst_port_entropy +
                                                                     (1 - alpha) * self.info_entropy[ip_addr]['sdst_port'][PREDICT][-1])
                self.info_entropy[ip_addr]['bytes_per_pkt'][PREDICT].append(alpha * curr_bytes_per_pkt_entropy +
                                                                     (1 - alpha) * self.info_entropy[ip_addr]['bytes_per_pkt'][PREDICT][-1])

            if len(self.info_entropy[ip_addr]['src_ip'][ACTUAL]) >= MAX_ENTROPY_COUNT:
                self.info_entropy[ip_addr]['src_ip'][ACTUAL].pop(0)
                self.info_entropy[ip_addr]['src_ip'][PREDICT].pop(0)
                self.info_entropy[ip_addr]['dst_ip'][ACTUAL].pop(0)
                self.info_entropy[ip_addr]['dst_ip'][PREDICT].pop(0)
                self.info_entropy[ip_addr]['src_port'][ACTUAL].pop(0)
                self.info_entropy[ip_addr]['src_port'][PREDICT].pop(0)
                self.info_entropy[ip_addr]['dst_port'][ACTUAL].pop(0)
                self.info_entropy[ip_addr]['dst_port'][PREDICT].pop(0)
                self.info_entropy[ip_addr]['bytes_per_pkt'][ACTUAL].pop(0)
                self.info_entropy[ip_addr]['bytes_per_pkt'][PREDICT].pop(0)

            self.info_entropy[ip_addr]['src_ip'][ACTUAL].append(curr_src_ip_entropy)
            self.info_entropy[ip_addr]['src_ip'][ACTUAL].append(curr_dst_ip_entropy)
            self.info_entropy[ip_addr]['src_ip'][ACTUAL].append(curr_src_port_entropy)
            self.info_entropy[ip_addr]['src_ip'][ACTUAL].append(curr_dst_port_entropy)
            self.info_entropy[ip_addr]['src_ip'][ACTUAL].append(curr_bytes_per_pkt_entropy)

        time.sleep(POLLING_TIME)

    def parser_netstream_packet(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 6666))
        while True:
            buf, addr = sock.recvfrom(MAX_SIZE_OF_NS_PACKET)
            self.logger.info("receive netstream packet from %s", addr)
            system_ip_addr = addr[0]
            (version, count) = struct.unpack('!HH', buf[0:4])
            if version != 5:
                continue
            # It's pretty unlikely you'll ever see more then 1000 records in a 1500 byte UDP packet
            if count <= 0 or count > 30:
                continue

            #uptime = socket.ntohl(struct.unpack('I',buf[4:8])[0])
            #epochseconds = socket.ntohl(struct.unpack('I',buf[8:12])[0])
            for i in range(0, count):
                base = SIZE_OF_HEADER + (i * SIZE_OF_RECORD)
                nsdata = {}
                nsdata['protocol'] = struct.unpack('B', buf[base+38:base+39])[0]
                if nsdata['protocol'] != IP_TCP:
                    continue

                if not system_ip_addr in self.info_entropy:
                    self.info_entropy[system_ip_addr] = {'src_ip':([], []), 'dst_ip':([], []),
                                                         'src_port':([], []), 'dst_port':([], []),
                                                         'bytes_per_pkt':([], [])}

                nsdata['system_ip'] = system_ip_addr
                nsdata['src_ip'] = struct.unpack('!I', buf[base+0:base+4])[0]
                nsdata['dst_ip'] = struct.unpack('!I', buf[base+4:base+8])[0]

                data = struct.unpack('!IIIIHH', buf[base+16:base+36])
                nsdata['bytes_per_pkt'] = data[1] // data[0]
                nsdata['src_port'] = data[4]
                nsdata['dst_port'] = data[5]
                nsdata['timestamp'] = int(time.time())
                #self.logger.info('nsdata : %s', nsdata)
                self.que.put(nsdata) 

def check_if_exists(key, net_dict):
    if key in net_dict:
        net_dict[key] = net_dict[key] + 1
    else:
        net_dict[key] = 1

def cal_info_entropy(num, net_dict):
    info_entropy = 0.0
    for n in net_dict.values():
        info_entropy = info_entropy + n / num * math.log(2, n / num)
    return -1 * info_entropy
