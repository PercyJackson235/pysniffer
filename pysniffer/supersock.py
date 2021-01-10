import socket
from netifaces import gateways
from typing import Union
from pysniffer import osi


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
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))  # noqa: E501
        self.sock = sock
        if iface is None:
            iface = gateways().get(socket.AF_INET)
            if iface is not None:
                iface = iface[0][1]
            else:
                iface = gateways().get('default')
                if iface is None:
                    msg = "Was not given an interface to listen on and could "
                    msg += "not find default gateway!"
                    raise OSError(msg)
                else:
                    iface = iface.get(socket.AF_INET)[1]
        self.sock.bind((iface, 0))

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

    def recv(self, buffize: int = 65535):
        return self.sock.recvfrom(buffize)[0]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __repr__(self):
        return str(self.sock).replace("socket.socket", self.__class__.__name__)

    __str__ = __repr__
