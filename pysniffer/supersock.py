import socket
from netifaces import gateways, ifaddresses
from typing import Union
from pysniffer import osi
import sys
import pcap


if any(map((lambda x: x in sys.platform.lower()), ("lin", "dar", "os2"))):
    AF_PACKET = socket.AF_PACKET
    address_pos = 1
elif any(map((lambda x: x in sys.platform.lower()), ("win", "cyg"))):
    AF_PACKET = socket.AF_INET
    address_pos = 0
else:
    AF_PACKET = socket.AF_PACKET
    address_pos = 1


class SuperSocket(object):
    """iface is the interface to listen on.
       sock is a socket.socket.
            Don't use unless you want a very specific socket configuration
       proto is the EtherType to listen for. valid options are ip, ipv6, all"""
    def __init__(self, iface: str = None, proto: str = None, sock: socket.socket = None):  # noqa: E501
        if proto is None:
            proto = osi.ethernettype['ALL']  # Refers EtherType noqa: E501
        else:
            proto = osi.ethernettype.get(proto.upper())
            if proto is None:
                proto = osi.ethernettype['ALL']
        if sock is None:
            if hasattr(socket, 'AF_PACKET'):
                sock = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.htons(proto))  # noqa: E501
            else:
                sock = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.htons(0x800)) # socket.IPPROTO_IP)
        self.sock = sock
        if iface is None:
            iface = gateways().get(socket.AF_INET)
            if iface is not None:
                iface = iface[0][1]
                if not hasattr(socket, 'AF_PACKET'):
                    iface = ifaddresses(iface).get(socket.AF_INET)[0]['addr']
                print(iface)
            else:
                iface = gateways().get('default')
                if iface is None:
                    msg = "Was not given an interface to listen on and could "
                    msg += "not find default gateway!"
                    raise OSError(msg)
                else:
                    iface = iface.get(socket.AF_INET)
                    if iface is None:
                        msg = "Was not given an interface to listen on and could "
                        msg += "not find default gateway!"
                        raise OSError(msg)
                    iface = iface[address_pos]
        print(iface)
        self.sock.bind((iface, 0))
        if not hasattr(socket, 'AF_PACKET'):
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self._pack_list = []
        self.sock.close()
        self.sock = pcap.pcap()

    def close(self):
        self.sock.close()

    def send(self, ip: str, packet: Union[str, bytes]):
        if not isinstance(packet, (str, bytes)):
            raise ValueError(f"send expects str or bytes, not {type(packet)}")
        if isinstance(packet, str):
            packet = packet.encode()
        return self.sock.sendto(packet, (ip, 0))

    @property
    def fileno(self):
        return self.sock.fileno()

    if hasattr(socket, 'AF_PACKET'):
        def recv(self, buffize: int = 65535):
            return self.sock.recvfrom(buffize)[0]
    else:
        def recv(self):
            # returns a list of tuples(milliseconds, data)
            if len(self._pack_list) <= 1:
                self._pack_list.extend(d for t, d in self.sock.readpkts())
            return self._pack_list.pop(0)

    def __iter__(self):
        return self

    def __next__(self):
        return self.recv()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __repr__(self):
        return str(self.sock).replace("socket.socket", self.__class__.__name__)

    __str__ = __repr__
