import struct
import time
import math
import socket
from multiprocessing import Process, Queue
import numpy as np

from ryu.base import app_manager


SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48
MAX_SIZE_OF_NS_PACKET = 1500
IP_TCP = 6
POLLING_TIME = 60
MAX_ENTROPY_COUNT = 360
ACTUAL = 0
PREDICT = 1
DETECT_FLAG = False

class NetStreamAnalyzer(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(NetStreamAnalyzer, self).__init__(*args, **kwargs)
        self.info_entropy = {}
        self.que = Queue()
        self.recv_ns_pkt = Process(target=self.parser_netstream_packet)
        self.detect_anomaly = Process(target=self.detect_tcp_syn_flooding)
        self.recv_ns_pkt.start()
        self.detect_anomaly.start()

    def detect_tcp_syn_flooding(self):
        while True:
            timestamp = int(time.time())
            netstream_record = {}
            alpha = 0.2

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
                    netstream_record[system_ip_addr]['flow_count'] = \
                                    netstream_record[system_ip_addr]['flow_count'] + 1
                else:
                    self.que.put(nsdata)
                    break
            #calculate information entropy for each netstream system
            
            for system_ip, ip_entropy_seq in self.info_entropy.items():
                flow_count = 0
                curr_src_ip_entropy = 0
                curr_dst_ip_entropy = 0
                curr_src_port_entropy = 0
                curr_dst_port_entropy = 0
                curr_bytes_per_pkt_entropy = 0
                if system_ip in netstream_record:
                    flow_count = netstream_record[system_ip]['flow_count']
                    curr_src_ip_entropy = cal_info_entropy(flow_count, netstream_record[system_ip]['src_ip'])
                    curr_dst_ip_entropy = cal_info_entropy(flow_count, netstream_record[system_ip]['dst_ip'])
                    curr_src_port_entropy = cal_info_entropy(flow_count, netstream_record[system_ip]['src_port'])
                    curr_dst_port_entropy = cal_info_entropy(flow_count, netstream_record[system_ip]['dst_port'])
                    curr_bytes_per_pkt_entropy = cal_info_entropy(flow_count, netstream_record[system_ip]['bytes_per_pkt'])
                # if flow_count == 0 and not ip_entropy_seq['src_ip'][ACTUAL]:
                    # continue

                #use exponential smoothing predicting model
                if not ip_entropy_seq['src_ip'][ACTUAL]:
                    ip_entropy_seq['src_ip'][PREDICT].append(curr_src_ip_entropy)
                    ip_entropy_seq['dst_ip'][PREDICT].append(curr_dst_ip_entropy)
                    ip_entropy_seq['src_port'][PREDICT].append(curr_src_port_entropy)
                    ip_entropy_seq['dst_port'][PREDICT].append(curr_dst_port_entropy)
                    ip_entropy_seq['bytes_per_pkt'][PREDICT].append(curr_bytes_per_pkt_entropy)
                else:
                    #compare with the predict information entropy
                    src_ip_std = np.std(ip_entropy_seq['src_ip'][ACTUAL], ddof=1)
                    dst_ip_std = np.std(ip_entropy_seq['dst_ip'][ACTUAL], ddof=1)
                    src_port_std = np.std(ip_entropy_seq['src_port'][ACTUAL], ddof=1)
                    dst_port_std = np.std(ip_entropy_seq['dst_port'][ACTUAL], ddof=1)
                    bytes_per_pkt_std = np.std(ip_entropy_seq['bytes_per_pkt'][ACTUAL], ddof=1)

                    if abs(ip_entropy_seq['src_ip'][PREDICT][-1] - curr_src_ip_entropy) >= 3 * src_ip_std and \
                    abs(ip_entropy_seq['dst_ip'][PREDICT][-1] - curr_dst_ip_entropy) >= 3 * dst_ip_std and \
                    abs(ip_entropy_seq['src_port'][PREDICT][-1] - curr_src_port_entropy) >= 3 * src_port_std and \
                    abs(ip_entropy_seq['dst_port'][PREDICT][-1] - curr_dst_port_entropy) >= 3 * dst_port_std and \
                    abs(ip_entropy_seq['bytes_per_pkt'][PREDICT][-1] - curr_bytes_per_pkt_entropy) >= 3 * bytes_per_pkt_std:
                        self.logger.info('Waring: the host(%s) may be under TCP SYN flooding attack!(%s)', ip_addr, \
                                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

                ip_entropy_seq['src_ip'][PREDICT].append(alpha * curr_src_ip_entropy + \
                                                        (1 - alpha) * ip_entropy_seq['src_ip'][PREDICT][-1])
                ip_entropy_seq['dst_ip'][PREDICT].append(alpha * curr_dst_ip_entropy + \
                                                        (1 - alpha) * ip_entropy_seq['dst_ip'][PREDICT][-1])
                ip_entropy_seq['src_port'][PREDICT].append(alpha * curr_src_port_entropy + \
                                                        (1 - alpha) * ip_entropy_seq['src_port'][PREDICT][-1])
                ip_entropy_seq['dst_port'][PREDICT].append(alpha * curr_dst_port_entropy + \
                                                        (1 - alpha) * ip_entropy_seq['sdst_port'][PREDICT][-1])
                ip_entropy_seq['bytes_per_pkt'][PREDICT].append(alpha * curr_bytes_per_pkt_entropy + \
                                                                (1 - alpha) * ip_entropy_seq['bytes_per_pkt'][PREDICT][-1])

                ip_entropy_seq['src_ip'][ACTUAL].append(curr_src_ip_entropy)
                ip_entropy_seq['dst_ip'][ACTUAL].append(curr_dst_ip_entropy)
                ip_entropy_seq['src_port'][ACTUAL].append(curr_src_port_entropy)
                ip_entropy_seq['dst_port'][ACTUAL].append(curr_dst_port_entropy)
                ip_entropy_seq['bytes_per_pkt'][ACTUAL].append(curr_bytes_per_pkt_entropy)

                if len(ip_entropy_seq['src_ip'][ACTUAL]) >= MAX_ENTROPY_COUNT:
                    ip_entropy_seq['src_ip'][ACTUAL].pop(0)
                    ip_entropy_seq['src_ip'][PREDICT].pop(0)
                    ip_entropy_seq['dst_ip'][ACTUAL].pop(0)
                    ip_entropy_seq['dst_ip'][PREDICT].pop(0)
                    ip_entropy_seq['src_port'][ACTUAL].pop(0)
                    ip_entropy_seq['src_port'][PREDICT].pop(0)
                    ip_entropy_seq['dst_port'][ACTUAL].pop(0)
                    ip_entropy_seq['dst_port'][PREDICT].pop(0)
                    ip_entropy_seq['bytes_per_pkt'][ACTUAL].pop(0)
                    ip_entropy_seq['bytes_per_pkt'][PREDICT].pop(0)

            time.sleep(POLLING_TIME)

    def parser_netstream_packet(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 6677))
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
