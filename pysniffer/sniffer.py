from pysniffer import decoders
from pysniffer.supersock import SuperSocket


class Sniffer(object):
    def __init__(self, logfile: str = None, iface: str = None, sock: SuperSocket = None):  # noqa : E501
        if sock is None:
            self.sock = SuperSocket(iface=iface)
        else:
            self.sock = sock

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def shutdown(self):
        self.sock.close()

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
                    transport, data = decoders.transport_layer.get(network.Proto)(data)
                except Exception as e:
                    print(f'Error occurred: {e!r}')
                    raise
                decoders.pprint(eth_header, network, transport, data)
            except KeyboardInterrupt:
                self.shutdown()
                print()
                break
