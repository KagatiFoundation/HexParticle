import ctypes

# --- IPv4 Protocol Numbers (assigned by IANA) ---
# Used to identify the next level protocol in the IP header 'proto' field
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

# Mapping for human-readable output during packet dissection
IPV4_PROTOCOL_NAMES = {
    IPV4_ICMP:        "ICMP(Internet Control Message Protocol)",
    IPV4_IGMP:        "IGMP(Internet Group Management Protocol)",
    IPV4_TCP:         "TCP(Transmission Control Protocol)",
    IPV4_UDP:         "UDP(User Datagram Protocol)",
    IPV4_IPV6_ROUTE:  "IPv6-Route(Routing Header for IPv6)",
    IPV4_DSR:         "DSR(Dynamic Source Routing Protocol)",
    IPV4_SWIPE:       "SwIPe(Swipe IP Security Protocol)",
    IPV4_TLSP:        "TLSP(Transport Layer Security Protocol)",
    IPV4_SKIP:        "SKIP(Simple Key Management for IP)",
    IPV4_SAT_EXPAK:   "SAT-EXPAK(SATNET and Backroom EXPAK)",
    IPV4_EIGRP:       "EIGRP(Enhanced Interior Gateway Routing Protocol)",
    IPV4_OSPF:        "OSPF(Open Shorted Path First)",
    IPV4_L2TP:        "L2TP(Layer 2 Tunneling Protocol version 3)",
}

# --- Layer 2 EtherTypes ---
# Used in the Ethernet frame to determine which protocol is encapsulated
ETHER_TYPE_IPV4 = 0x0800 
ETHER_TYPE_IPV6 = 0x86DD 
ETHER_TYPE_ARP 	= 0x0806 

ETHER_TYPE_NAMES = {
    ETHER_TYPE_ARP:		"Address Resolution Protocol",
    ETHER_TYPE_IPV4:	"Internet Protocol Version 4",
    ETHER_TYPE_IPV6:	"Internet Protocol Version 6",
}


# --- ARP Operation Types ---
ARP_REQUEST 	= 1
ARP_RESPONSE	= 2


# Represents a fixed-size array for IPv4 addresses (uint8_t[4])
CT_IPV4_ADDRESS = ctypes.c_uint8 * 4
# Represents a fixed-size array for MAC addresses (uint8_t[6])
CT_MAC_ADDRESS  = ctypes.c_uint8 * 6

def get_protocol_name(proto_number: int) -> str:
    return IPV4_PROTOCOL_NAMES.get(proto_number, "Unknown Protocol")

class ProtocolType:
    ETH		= 0
    IPV4 	= 1
    IPV6 	= 2
    ARP 	= 3
    TCP 	= 4
    UDP 	= 5


# Protocol specific constants
COMMON_PORTS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 443: "HTTPS", 3389: "RDP"
}


# --- Hierarchical Node Structure ---
class ProtocolNode(ctypes.Structure):
    """
    Python representation of the C linked-list node.
    Each node points to a specific protocol header and the next layer.
    """
    pass

ProtocolNode._fields_ = [
    ("type", 	ctypes.c_int),                  # Internal ProtocolType
    ("hdr", 	ctypes.c_void_p),               # Pointer to the actual header struct
    ("hdr_len", ctypes.c_uint32),               # Size of the header (for variable length parsing)
    ("next", 	ctypes.POINTER(ProtocolNode))   # Link to the encapsulated protocol
]

# --- Protocol Header Definitions ---

class EtherHeader(ctypes.Structure):
    """Maps to EtherHeader_t"""
    _pack_ = 1
    _fields_ = [
        ('src_mac', 	CT_MAC_ADDRESS), 
        ('dst_mac', 	CT_MAC_ADDRESS),
        ('type', 		ctypes.c_uint16),
        ('len', 		ctypes.c_uint32)
    ]

class IPV4Header(ctypes.Structure):
    """Maps to IPv4_t. Represents the standard 20-byte IPv4 header."""
    _pack_ = 1
    _fields_ = [
        ('ver_ihl', 	ctypes.c_uint8),        # Version (4 bits) + IHL (4 bits)
        ('dscp_ecn', 	ctypes.c_uint8),        # DiffServ + ECN
        ('len', 		ctypes.c_uint16),       # Total Packet Length
        ('id', 			ctypes.c_uint16),       # Identification
        ('flags_off', 	ctypes.c_uint16),       # Flags + Fragment Offset
        ('ttl', 		ctypes.c_uint8),        # Time to Live
        ('proto', 		ctypes.c_uint8),        # Protocol
        ('chk', 		ctypes.c_uint16),       # Header Checksum
        ('src', 		CT_IPV4_ADDRESS),       # Source IP
        ('dst', 		CT_IPV4_ADDRESS)        # Destination IP
    ]


class ARPHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('htype', 	ctypes.c_uint16),
        ('ptype', 	ctypes.c_uint16),
        ('hlen', 	ctypes.c_uint8),
        ('plen', 	ctypes.c_uint8),
        ('op', 		ctypes.c_uint16),
        ('sha', 	CT_MAC_ADDRESS),
        ('spa', 	CT_IPV4_ADDRESS),
        ('tha', 	CT_MAC_ADDRESS),
        ('tpa', 	CT_IPV4_ADDRESS)
    ]


class TCPHeader(ctypes.Structure):
    """Maps to TCPHeader_t. Represents the standard TCP segment header."""
    _pack_ = 1
    _fields_ = [
        ("sport", 	ctypes.c_uint16),    # Source Port
        ("dport", 	ctypes.c_uint16),    # Destination Port
        ("seq", 	ctypes.c_uint32),      # Sequence Number
        ("ack", 	ctypes.c_uint32),      # Acknowledgment Number
        ("off_res", ctypes.c_uint8),   # Data Offset + Reserved bits
        ("flags", 	ctypes.c_uint8),     # Control Flags (SYN, ACK, FIN, etc.)
        ("win", 	ctypes.c_uint16),      # Window Size
        ("chk", 	ctypes.c_uint16),      # Checksum
        ("urg", 	ctypes.c_uint16),      # Urgent Pointer
    ]


class UDPHeader(ctypes.Structure):
    """Maps to UDPHeader_t. Represents the standard UDP segment header."""
    _pack_ = 1
    _fields_ = [
        ('sport', ctypes.c_uint16),
        ('dport', ctypes.c_uint16),
        ('length', ctypes.c_uint16),
        ('cksum', ctypes.c_uint16)
    ]


__all__ = [
    'IPV4_PROTOCOL_NAMES', 
    'ETHER_TYPE_IPV4', 
    'TCPHeader', 
    'ProtocolNode', 
    'ProtocolType',
    'EtherHeader',
    'IPV4Header',
    'ARPHeader'
]