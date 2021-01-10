from pysniffer import decoders
from pysniffer.supersock import SuperSocket
from typing import Union
from socket import socket
import sys


class Sniffer(object):
    def __init__(self, logfile: str = None, iface: str = None, proto: str = None,  # noqa : E501
                 sock: Union[SuperSocket, socket] = None):
        if sock is None:
            self.sock = SuperSocket(iface=iface, proto=proto)
        elif isinstance(sock, SuperSocket):
            self.sock = sock
        elif isinstance(sock, socket):
            self.sock = SuperSocket(iface=iface, proto=proto, sock=sock)
        else:
            msg = "sock must be type socket.socket or SuperSocket, "
            msg += f"not {type(sock)}."
            raise TypeError(msg)
        self.log = False
        if bool(logfile):
            if isinstance(logfile, str):
                self.log_create(logfile)
            else:
                raise TypeError(f"logfile must be str, not {type(logfile)}.")

    if any(map((lambda x: x in sys.platform.lower()), ("lin", "dar", "os2"))):
        def log_create(self, logfile):
            import os
            import pwd
            suid = os.getuid()
            user = os.getlogin()
            self.logfile = open(logfile, 'ab')
            self.log = True
            if pwd.getpwuid(suid).pw_name != user:
                userid = pwd.getpwnam(user)
                os.chown(logfile, userid.pw_uid, userid.pw_gid)
    elif any(map((lambda x: x in sys.platform.lower()), ("win", "cyg"))):
        def log_create(self, logfile):
            self.logfile = open(logfile, 'ab')
            self.log = True
    else:
        def log_create(self, logfile):
            import os
            import pwd
            suid = os.getuid()
            user = os.getlogin()
            self.logfile = open(logfile, 'ab')
            self.log = True
            if pwd.getpwuid(suid).pw_name != user:
                userid = pwd.getpwnam(user)
                os.chown(logfile, userid.pw_uid, userid.pw_gid)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def shutdown(self):
        self.sock.close()
        if self.log:
            self.logfile.close()

    def start(self):
        while True:
            try:
                eth_header, data = decoders.ethernet(self.sock.recv())
                # This is needed until I have decoders for all types of traffic
                if decoders.network_layer.get(eth_header.EthType) is None:
                    continue
                network = ''
                transport = ''
                try:
                    network, data = decoders.network_layer.get(eth_header.EthType)(data)  # noqa: E501
                    transport, data = decoders.transport_layer.get(network.Proto)(data)  # noqa : E501
                except Exception as e:
                    print(f'Error occurred: {e!r}')
                    raise
                result = decoders.pprint(eth_header, network, transport, data)
                if self.log:
                    self.logfile.write(result)
            except KeyboardInterrupt:
                self.shutdown()
                print()
                break
