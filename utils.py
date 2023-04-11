import math

# whisper

class PacketMetaData:
    def __init__(self, src_addr: int, proto_code: int, pkt_length: int, timestamp: float):
        self.src_addr = src_addr
        self.proto_code = proto_code
        self.pkt_length = pkt_length
        self.timestamp = timestamp

type_identity_mp = {
    "TYPE_TCP_SYN": 1,
    "TYPE_TCP_FIN": 40,
    "TYPE_TCP_RST": 1,
    "TYPE_TCP_ACK": 1000,
    "TYPE_TCP": 1000,
    "TYPE_UDP": 3,
    "TYPE_ICMP": 10,
    "TYPE_IGMP": 9,
    "TYPE_UNKNOWN": 10,
}

import dpkt
import struct
import pandas as pd
import socket
import os


def pcap2csv_by_dpkt(filename: str, save_path: str = None, pcapng: bool = False) -> None:
    if not pcapng:
        fpcap = dpkt.pcap.Reader(open(filename, "rb"))
        suffix = ".pcap"
    else:
        fpcap = dpkt.pcapng.Reader(open(filename, "rb"))
        suffix = ".pcapng"
    all_fields = []
    for ts, buf in fpcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        src_port = ""
        dst_port = ""
        tos = ip.tos
        id = ip.id
        ttl = ip.ttl
        chksum = ip.sum
        flags = ip._flags_offset
        payload = ""
        tcp_window = ""
        tcp_dataoffset = ""
        udp_length = ""
        protocol = ip.p
        proto_code = type_identity_mp["TYPE_UNKNOWN"]
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            payload = tcp.data
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_window = tcp.win
            tcp_dataoffset = tcp.off
            # check tcp flags
            if tcp.flags & dpkt.tcp.TH_SYN:
                proto_code = type_identity_mp["TYPE_TCP_SYN"]
            elif tcp.flags & dpkt.tcp.TH_FIN:
                proto_code = type_identity_mp["TYPE_TCP_FIN"]
            elif tcp.flags & dpkt.tcp.TH_RST:
                proto_code = type_identity_mp["TYPE_TCP_RST"]
            else:
                proto_code = type_identity_mp["TYPE_TCP"]
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            if not isinstance(udp, dpkt.udp.UDP):
                print("udp is not instance of dpkt.udp.UDP")
                print(f"protocol: {ip.p}")
                continue
            payload = udp.data
            src_port = udp.sport
            dst_port = udp.dport
            udp_length = udp.ulen
            proto_code = type_identity_mp["TYPE_UDP"]
        else:
            proto_code = type_identity_mp["TYPE_UNKNOWN"]

        src_addr = struct.unpack("!I", ip.src)[0]
        dst_addr = struct.unpack("!I", ip.dst)[0]
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        pkt_length = len(buf)
        all_fields.append([src_addr, dst_addr, src_ip, dst_ip, src_port, dst_port, 
                           protocol, proto_code, pkt_length, ts,
                           tos, id, ttl, chksum, flags, tcp_window, tcp_dataoffset, udp_length,
                           payload])
    if save_path is None:
        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
        except:
            pass
    sp = save_path if save_path is not None else filename.replace(suffix, ".csv")
    pd.DataFrame(all_fields).to_csv(sp, sep=","
                , header=["src_addr", "dst_addr", "src_ip", "dst_ip", "src_port", "dst_port", 
                        "protocol", "proto_code", "pkt_length", "timestamp", "tos", "id", 
                        "ttl", "chksum", "flags", "tcp_window", "tcp_dataoffset", "udp_length",
                        "payload"], index=False)
    

import subprocess
def pcap2csv_by_tshark(input_file: str) -> None:
    output_file = input_file.replace(".pcap", ".csv")
    fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ipv6.src -e ipv6.dst"
    cmd = f"tshark -r {input_file}  -T fields {fields} -E header=y -E separator=, > {output_file}"
    print(cmd)
    subprocess.call(cmd, shell=True)


from scapy.all import IP, TCP, UDP, PcapReader, PcapNgReader

def pcap2csv_by_scapy(filename: str, save_path: str = None, pcapng: bool = False):
    if not pcapng:
        fpcap = PcapReader(filename)
        suffix = ".pcap"
    else:
        fpcap = PcapNgReader(filename)
        suffix = ".pcapng"
    all_fields = []
    for pkt in fpcap:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            src_port = ""
            dst_port = ""
            protocol = ip.proto
            proto_code = type_identity_mp["TYPE_UNKNOWN"]
            version = ip.version
            ihl = ip.ihl
            tos = ip.tos
            id = ip.id
            flags = ip.flags
            frag = ip.frag
            ttl = ip.ttl
            chksum = ip.chksum
            # payload = ip.payload
            payload = ""
            if ip.proto == 6:
                tcp = pkt[TCP]
                payload = bytes(tcp.payload)
                src_port = tcp.sport
                dst_port = tcp.dport
                # check tcp flags
                if tcp.flags & 0x02:
                    proto_code = type_identity_mp["TYPE_TCP_SYN"]
                elif tcp.flags & 0x01:
                    proto_code = type_identity_mp["TYPE_TCP_FIN"]
                elif tcp.flags & 0x04:
                    proto_code = type_identity_mp["TYPE_TCP_RST"]
                else:
                    proto_code = type_identity_mp["TYPE_TCP"]
            elif ip.proto == 17:
                try:
                    udp = pkt[UDP]
                    payload = bytes(udp.payload)
                    src_port = udp.sport
                    dst_port = udp.dport
                except:
                    print("valid udp packet")
                    continue
            pkt_length = pkt.len
        ts = pkt.time
        all_fields.append([src_ip, dst_ip, src_port, dst_port, protocol, proto_code, pkt_length, ts, 
                            version, ihl, tos, id, flags, frag, ttl, chksum ,payload])
    if save_path is None:
        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
        except:
            pass
    sp = save_path if save_path is not None else filename.replace(suffix, ".csv")
    pd.DataFrame(all_fields).to_csv(sp, sep=","
                , header=["src_ip", "dst_ip", "src_port", "dst_port", 
                        "protocol",  "proto_code", "pkt_length", "timestamp", 
                        "version", "ihl", "tos", "id", "flags", "frag", "ttl",
                        "chksum", "payload"], index=False)


def weight_transform(info: PacketMetaData) -> float:
    return info.pkt_length * 10 + info.proto_code / 10 + -math.log2(info.timestamp) * 15.68

# FlowLens

class Packet:
    def __init__(self, 
                 src_addr: int = None, 
                 dst_addr: int = None, 
                 src_ip: str = None,
                 dst_ip: str = None,
                 src_port: int = None,
                 dst_port: int = None,
                 protocol: int = None,
                 proto_code: int = None, 
                 pkt_length: int = None, 
                 timestamp: float = None,
                 ttl: int = None,
                 tcp_window: int = None,
                 tcp_dataoffset: int = None,
                 udp_length: int = None,
                 label: str = None
                 ) -> None:
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.proto_code = proto_code
        self.pkt_length = pkt_length
        self.timestamp = timestamp
        self.ttl = ttl
        self.tcp_window = tcp_window
        self.tcp_dataoffset = tcp_dataoffset
        self.udp_length = udp_length
        self.label = label

    def __str__(self) -> str:
        return f"Packet({self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} {self.protocol} {self.pkt_length} {self.timestamp})"
    
    def key(self, type: str = "default") -> str:
        def to_str(x):
            return str(x) if x is not None else "NULL"
        if type == "default":
            return self.src_ip + ":" + to_str(self.src_port) + " -> " + self.dst_ip + ":" + to_str(self.dst_port) + " " + to_str(self.protocol)
        elif type == "whisper":
            return self.src_ip


import numpy as np
MIN_TIME_INTERVAL = 1e-8
IP_MTU = 1500
UDP_MTU = 1472
TCP_WINDOW_MIN = 1
TCP_WINDOW_MAX = 65535
TCP_DO_MIN = 5
TCP_DO_MAX = 15
TTL_MIN = 1
TTL_MAX = 255

class Flow:
    def __init__(self) -> None:
        self.src_addr = None
        self.dst_addr = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.protocol = None
        self.time_start = None
        self.time_end = None
        self.label = None
        self.pkt_bytes = []
        self.pkt_proto_codes = []
        self.time_interval = []
        self.ttl = []
        self.tcp_window = []
        self.tcp_dataoffset = []
        self.udp_length = []
        
    
    def key(self, type: str = "default") -> str:
        def to_str(x):
            return str(x) if x is not None else "NULL"
        if type == "default":
            return self.src_ip + ":" + to_str(self.src_port) + " -> " + self.dst_ip + ":" + to_str(self.dst_port) + " " + to_str(self.protocol)
        elif type == "whisper":
            return self.src_ip

    def add_packet(self, packet: Packet) -> None:
        if len(self.pkt_bytes) == 0: # first packet
            self.src_addr = packet.src_addr
            self.dst_addr = packet.dst_addr
            self.src_ip = packet.src_ip
            self.dst_ip = packet.dst_ip
            self.src_port = packet.src_port
            self.dst_port = packet.dst_port
            self.protocol = packet.protocol
            self.label = packet.label
            self.time_start = packet.timestamp
            self.time_interval.append(MIN_TIME_INTERVAL)
        else:
            self.time_interval.append(packet.timestamp - self.time_end)
        
        self.time_end = packet.timestamp
        self.pkt_bytes.append(packet.pkt_length)
        self.pkt_proto_codes.append(packet.proto_code)
        self.ttl.append(packet.ttl)
        self.tcp_window.append(packet.tcp_window)
        self.tcp_dataoffset.append(packet.tcp_dataoffset)
        self.udp_length.append(packet.udp_length)

    def vector(self, feature_type: str = "whisper"):
        if feature_type == "whisper":
            res = [self.pkt_bytes[i] * 10 + self.pkt_proto_codes[i] / 10 + 
                   -math.log2(self.time_interval[i] + MIN_TIME_INTERVAL) * 15.68 
                   for i in range(len(self.pkt_bytes))]
            return res
        elif feature_type == "flowlens":
            BIN_SIZE_BYTE, BIN_SIZE_TIME = 4, 6
            MARKER_SIZE = 100
            vec_size, vec_time = [0] * MARKER_SIZE, [0] * MARKER_SIZE
            for i in range(len(self.pkt_bytes)):
                size = self.pkt_bytes[i] / BIN_SIZE_BYTE
                time = self.time_interval[i] / BIN_SIZE_TIME
                idx_size = int(size) if size < MARKER_SIZE else MARKER_SIZE - 1
                idx_time = int(time) if time < MARKER_SIZE else MARKER_SIZE - 1
                vec_size[idx_size] += 1
                vec_time[idx_time] += 1
            return vec_size, vec_time, self.label
        else:
            return None
        
    def packet_vector(self, agg_type: str = "mean"):
        pkt_bytes = list(map(lambda x: x / IP_MTU, filter(lambda x: x is not None, self.pkt_bytes)))
        ttl = list(map(lambda x: x / TTL_MAX, filter(lambda x: x is not None, self.ttl)))
        tcp_window = list(map(lambda x: x / TCP_WINDOW_MAX, filter(lambda x: x is not None, self.tcp_window)))
        tcp_dataoffset = list(map(lambda x: x / TCP_DO_MAX, filter(lambda x: x is not None, self.tcp_dataoffset)))
        udp_length = list(map(lambda x: x / UDP_MTU, filter(lambda x: x is not None, self.udp_length)))
        if agg_type == "mean":
            vec = [np.mean(pkt_bytes), np.mean(ttl), np.mean(tcp_window), np.mean(tcp_dataoffset), np.mean(udp_length)]
        elif agg_type == "std":
            vec = [np.std(pkt_bytes), np.std(ttl), np.std(tcp_window), np.std(tcp_dataoffset), np.std(udp_length)]
        elif agg_type == "max":
            vec = [np.max(pkt_bytes), np.max(ttl), np.max(tcp_window), np.max(tcp_dataoffset), np.max(udp_length)]
        elif agg_type == "min":
            vec = [np.min(pkt_bytes), np.min(ttl), np.min(tcp_window), np.min(tcp_dataoffset), np.min(udp_length)]
        vec = [x if not math.isnan(x) else 0 for x in vec]
        return vec
    
    def packet_vector_simple(self):
        pkt_bytes = list(map(lambda x: x if not math.isnan(x) else 0, self.pkt_bytes))
        ttl = list(map(lambda x: x if not math.isnan(x) else 0, self.ttl))
        tcp_window = list(map(lambda x: x if not math.isnan(x) else 0, self.tcp_window))
        tcp_dataoffset = list(map(lambda x: x if not math.isnan(x) else 0, self.tcp_dataoffset))
        udp_length = list(map(lambda x: x if not math.isnan(x) else 0, self.udp_length))
        data = [pkt_bytes, ttl, tcp_window, tcp_dataoffset, udp_length, self.time_interval, [self.label] * len(pkt_bytes)]
        data = np.array(data).T.tolist()
        return data

def quantize(x: float, bin_size: int) -> int:
    return int(x / bin_size)