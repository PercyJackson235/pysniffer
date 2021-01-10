from pysniffer.sniffer import Sniffer


if __name__ == "__main__":
    import argparse
    from argparse import RawTextHelpFormatter as HelpFormat
    parser = argparse.ArgumentParser("PySniffer", formatter_class=HelpFormat,
                                     description="A packet sniffer written in python3.")  # noqa: E501
    parser.add_argument("-i", "--interface", default=None, dest="iface",
                        help="Inteface to listen on. Default is default gateway.")  # noqa: E501
    parser.add_argument("-P", "--protocol", dest="proto",
                        default=None, choices=['ip', 'ipv6', 'all'],
                        help="Protocol to listen for. Valid choices are ip, ipv6, all."  # noqa: E501
                        "\nDefault is all.")
    parser.add_argument("-l", "--logfile", help="Log file to use.")
    with Sniffer(**vars(parser.parse_args())) as sniffer:
        sniffer.start()
