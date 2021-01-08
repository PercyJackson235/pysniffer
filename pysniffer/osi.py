from collections import namedtuple

ipv4_packet = namedtuple('IPv4', ('Version', 'IP_Header_Len', 'DSCP', 'ECN',
                                  'Total_Length', 'ID', 'IP_Flags', 'Frag_Offset',  # noqa: E501
                                  'ttl', 'Proto', 'Checksum', 'Source_IP',
                                  'Dest_IP', 'IP_Options'))

tcp_packet = namedtuple('TCP', ('Source_Port', 'Dest_Port', 'Seq_Num',
                                'Ack_Num', 'Data_Offset', 'Res',
                                'TCP_Flags', 'MTU', 'Checksum',
                                'Urg_Pointer', 'TCP_Options'))

udp_packet = namedtuple('UDP', ('Source_Port', 'Dest_Port', 'Length',
                                'Checksum'))

ether_packet = namedtuple('Ethernet', ['Dest_MAC', 'Source_MAC', 'EthType'])

base = ('Type', 'Code', 'Checksum')
icmp_packet = {4: namedtuple('ICMP', [*base, 'unused']),
               5: namedtuple('ICMP', [*base, 'IP_Address']),
               11: namedtuple('ICMP', [*base, 'unused']),
               13: namedtuple('ICMP', [*base, 'identifier', 'Time_Seq',
                                       'Origin_Timestamp', 'Receive_Timestamp',
                                       'Transmit_Timestamp']),
               14: namedtuple('ICMP', [*base, 'Identifier', 'Time_Seq',
                                       'Origin_Timestamp', 'Receive_Timestamp',
                                       'Transmit_Timestamp']),
               17: namedtuple('ICMP', [*base, 'Identifier', 'Seq', 'Address_Mask']),  # noqa: E501
               18: namedtuple('ICMP', [*base, 'Identifier', 'Seq', 'Address_Mask']),  # noqa: E501
               3: namedtuple('ICMP', [*base, 'unused', 'Next_Hop_MTU']),
               'default': namedtuple('ICMP', [*base, 'unknown1', 'unknown2'])}

icmptypes = {0: "echo-reply", 3: "dest-unreach", 4: "source-quench",
             5: "redirect", 8: "echo-request", 9: "router-advertisement",
             10: "router-solicitation", 11: "time-exceeded",
             12: "parameter-problem", 13: "timestamp-request",
             14: "timestamp-reply", 15: "information-request",
             16: "information-response", 17: "address-mask-request",
             18: "address-mask-reply", 30: "traceroute",
             31: "datagram-conversion-error", 32: "mobile-host-redirect",
             33: "ipv6-where-are-you", 34: "ipv6-i-am-here",
             35: "mobile-registration-request",
             36: "mobile-registration-reply", 37: "domain-name-request",
             38: "domain-name-reply", 39: "skip", 40: "photuris"}

icmpcodes = {3: {0: "network-unreachable", 1: "host-unreachable",
                 2: "protocol-unreachable", 3: "port-unreachable",
                 4: "fragmentation-needed", 5: "source-route-failed",
                 6: "network-unknown", 7: "host-unknown",
                 9: "network-prohibited", 10: "host-prohibited",
                 11: "TOS-network-unreachable", 12: "TOS-host-unreachable",
                 13: "communication-prohibited", 14: "host-precedence-violation",
                 15: "precedence-cutoff"},
             5: {0: "network-redirect", 1: "host-redirect",
                 2: "TOS-network-redirect", 3: "TOS-host-redirect"},
             11: {0: "ttl-zero-during-transit", 1: "ttl-zero-during-reassembly"},
             12: {0: "ip-header-bad", 1: "required-option-missing", },
             40: {0: "bad-spi", 1: "authentication-failed",
                  2: "decompression-failed", 3: "decryption-failed",
                  4: "need-authentification", 5: "need-authorization"}, }

# From /usr/include/linux/if_ether.h
ethernettype = {'IP': 0x0800, 'IPV6': 0x86DD, 'ARP': 0x0806, 'ALL': 0x0003}
