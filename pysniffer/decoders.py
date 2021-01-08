import struct
import binascii
import socket
from typing import Union
from enum import IntFlag
from pysniffer import osi


def ethernet(packet: bytes):
    header, payload = packet[:14], packet[14:]
    header = struct.unpack("!6s6s2s", header)
    header = tuple(map((lambda x: binascii.hexlify(x)), header))
    headers = []
    for mac in header[:2]:
        mac = mac.decode()
        headers.append(':'.join(mac[i:i + 2] for i in range(0, len(mac), 2)))
    headers.append(int(header[-1].decode(), 16))
    return osi.ether_packet(*headers), payload


IPV4_MIN = 20
IPV4_FIELDS = {1: lambda x: (4, (x - 64) * 4),
               2: lambda x: (x >> 2, int(f"{x:08b}"[6:], 2)),
               5: lambda x: (x >> 13, int(f"{x:016b}"[3:], 2)),
               9: lambda x: (socket.inet_ntoa(x),),
               10: lambda x: (socket.inet_ntoa(x),)}


def ipv4(packet: bytes):
    header_size = IPV4_MIN
    if packet[0] != 69:  # 69 == 0x45
        header_size = (packet[0] - 64) * 4  # 64 == 0x40
    header, payload = packet[:header_size], packet[header_size:]
    header = struct.unpack(f"!BBHHHBBH4s4s{header_size - IPV4_MIN}s", header)
    headers = []
    for pos, field in enumerate(header, 1):
        headers.extend(IPV4_FIELDS.get(pos, lambda x: (x,))(field))
    return osi.ipv4_packet(*headers), payload


TCP_FIELDS = {5: lambda x: ()}
TCP_MIN = 20
TCP_FLAGS = {'SYN': 0, 'PSH': 2, 'ACK': 3, 'FIN': 1, 'URG': 4,
             'ECE': 5, 'CWR': 6, 'NS': 7, 'RST': 0}


def tcp_length(field: Union[bytes, int]):
    if isinstance(field, bytes):
        field = struct.unpack('!H', field)[0]
        return int(f"{field:016b}"[:4], 2) * 4
    else:
        field = f"{field:016b}"
        return int(field[:4], 2) * 4, int(field[4:7], 2), TcpFlags(int(field[7:], 2))  # noqa: E501


def tcp(packet: bytes):
    header_size = tcp_length(packet[12:14])
    header, payload = packet[:header_size], packet[header_size:]
    header = struct.unpack(f"!HHLLHHHH{header_size - TCP_MIN}s", header)
    headers = []
    for pos, field in enumerate(header, 1):
        if pos != 5:
            headers.append(field)
        else:
            headers.extend(tcp_length(field))
    return osi.tcp_packet(*headers), payload


class TcpFlags(IntFlag):
    FIN = 2**0
    SYN = 2**1
    RST = 2**2
    PSH = 2**3
    ACK = 2**4
    URG = 2**5
    ECE = 2**6
    CWR = 2**7
    NS = 2**8

    def __str__(self):
        result = super().__str__().split('.')[-1].split('|')
        return f"<{'|'.join(sorted(result, key=lambda x: TCP_FLAGS[x]))}>"


def udp(packet: bytes):
    header, payload = packet[:8], packet[8:]
    header = struct.unpack("HHHH", header)
    return osi.udp_packet(*header), payload


def icmp(packet: bytes):
    icmptype = struct.unpack("!B", packet[:1])
    if not isinstance(icmptype, int):
        icmptype = icmptype[0]
    sep, fmt = ICMP_TYPE.get(icmptype, (8, "!BBHHH"))
    header, payload = icmp_unpack(packet, sep, fmt)
    wrapper = osi.icmp_packet.get(icmptype)
    if wrapper is None:
        wrapper = osi.icmp_packet['default']
    header = wrapper(*header)
    if header.Type in osi.icmptypes:
        temp = header._asdict()
        if header.Type in osi.icmpcodes:
            temp['Code'] = osi.icmpcodes[header.Type].get(header.Code, 0)
        temp['Type'] = osi.icmptypes[header.Type]
        header = wrapper(**temp)
    return header, payload


ICMP_TYPE = {4: (8, "!BBHL"), 5: (8, "!BBH4s"), 11: (8, "!BBHL"),
             13: (20, "!BBHHHLLL"), 14: (20, "!BBHHHLLL"),
             17: (12, "!BBHHHL"), 18: (12, "!BBHHHL"), 3: (8, "!BBHHH")}


def icmp_unpack(packet: bytes, sep: int, fmt: str):
    """Receives packet as bytes, sep is the sepration of header from data,
       and fmt is format string for unpacking data"""
    header, payload = packet[:sep], packet[sep:]
    header = struct.unpack(fmt, header)
    if 's' in fmt:
        ip = socket.inet_ntoa(header[-1])
        header = *header[:-1], ip
    return header, payload


# 0x86DD is ipv6, 0x0806 is arp
network_layer = {0x800: ipv4, 0x86DD: None, 0x0806: None}
transport_layer = {6: tcp, 17: udp, 1: icmp}


def pprint(eth, net, trans, data: bytes):
    result = f"S-MAC: {eth.Source_MAC} > D-MAC: {eth.Dest_MAC}| "
    net_name = trans.__class__.__name__
    if hasattr(trans, 'Source_Port'):
        result += net_name + f" {net.Source_IP}:{trans.Source_Port} "
        result += f"> {net.Dest_IP}:{trans.Dest_Port} | "
    else:
        result += net_name + f" {net.Source_IP} > {net.Dest_IP} | "
    if net_name.lower() == 'tcp':
        result += f"{net_name} "
        result += f"Flags: {trans.TCP_Flags!s} Seq: {trans.Seq_Num} "
        result += f"Ack: {trans.Ack_Num} Win: {trans.MTU}"
    elif net_name.lower() == 'udp':
        result += net_name + f" checksum: {trans.Checksum}, len: {trans.Length}"
    elif net_name.lower() == 'icmp':
        result += net_name + ' '.join(f"{k}: {v}" for k, v in trans._asdict().items())  # noqa: E501
    try:
        data = data.decode()
    except UnicodeError:
        pass
    print(result, data)
