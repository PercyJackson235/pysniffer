from pysniffer.sniffer import Sniffer


if __name__ == "__main__":
    with Sniffer() as sniffer:
        sniffer.start()



