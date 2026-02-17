import ctypes

IPV4_ICMP        = 0x01
IPV4_IGMP        = 0x02
IPV4_TCP         = 0x06
IPV4_UDP         = 0x11
IPV4_IPV6_ROUTE  = 0x2B
IPV4_DSR         = 0x20
IPV4_SWIPE       = 0x35
IPV4_TLSP        = 0x38
IPV4_SKIP        = 0x39
IPV4_SAT_EXPAK   = 0x40
IPV4_EIGRP       = 0x58
IPV4_OSPF        = 0x59
IPV4_L2TP        = 0x73


IPV4_PROTOCOL_NAMES = {
    IPV4_ICMP:       "ICMP(Internet Control Message Protocol)",
    IPV4_IGMP:       "IGMP(Internet Group Management Protocol)",
    IPV4_TCP:        "TCP(Transmission Control Protocol)",
    IPV4_UDP:        "UDP(User Datagram Protocol)",
    IPV4_IPV6_ROUTE: "IPv6-Route(Routing Header for IPv6)",
    IPV4_DSR:        "DSR(Dynamic Source Routing Protocol)",
    IPV4_SWIPE:      "SwIPe(Swipe IP Security Protocol)",
    IPV4_TLSP:       "TLSP(Transport Layer Security Protocol)",
    IPV4_SKIP:       "SKIP(Simple Key Management for IP)",
    IPV4_SAT_EXPAK:  "SAT-EXPAK(SATNET and Backroom EXPAK)",
    IPV4_EIGRP:      "EIGRP(Enhanced Interior Gateway Routing Protocol)",
    IPV4_OSPF:       "OSPF(Open Shorted Path First)",
    IPV4_L2TP:       "L2TP(Layer 2 Tunneling Protocol version 3)",
}


# EtherType(https://en.wikipedia.org/wiki/EtherType#Values)
ETHER_TYPE_IPV4 = 0x0800 # Internet Protocol Version 4 
ETHER_TYPE_IPV6 = 0x86DD # Internet Protocol Version 6
ETHER_TYPE_ARP 	= 0x0806 # Address Resolution Protocol


# ctypes IPV4 address
CT_IPV4_ADDRESS = ctypes.c_uint8 * 4


def get_protocol_name(proto_number: int) -> str:
    return IPV4_PROTOCOL_NAMES.get(proto_number, "Unknown Protocol")


class ProtocolType:
    ETH		= 0
    IPV4 	= 1
    IPV6 	= 2
    ARP 	= 3
    TCP 	= 4


class ProtocolNode(ctypes.Structure):
    pass


ProtocolNode._fields_ = [
    ("type", ctypes.c_int),
    ("hdr", ctypes.c_void_p),
    ("hdr_len", ctypes.c_uint32),
    ("next", ctypes.POINTER(ProtocolNode))
]


class EtherHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('src_mac', ctypes.c_char_p),
        ('dst_mac', ctypes.c_char_p),
        ('type', ctypes.c_uint16),
        ('len', ctypes.c_size_t)
	]


class IPV4Header(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('ver_ihl', ctypes.c_uint8),
        ('dscp_ecn', ctypes.c_uint8),
        ('len', ctypes.c_uint16),
        ('id', ctypes.c_uint16),
        ('flags_off', ctypes.c_uint16),
        ('ttl', ctypes.c_uint8),
        ('chk', ctypes.c_uint16),
        ('src', CT_IPV4_ADDRESS),
        ('dst', CT_IPV4_ADDRESS)
	]


class TCPHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("ack", ctypes.c_uint32),
        ("off_res", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("win", ctypes.c_uint16),
        ("chk", ctypes.c_uint16),
        ("urg", ctypes.c_uint16),
    ]


__all__ = [
    'IPV4_PROTOCOLS', 
    'ETHER_TYPE_IPV4', 
    'TCPHeader', 
    'ProtocolNode', 
    'ProtocolType',
    'PacketWrapper',
    'EtherHeader'
]