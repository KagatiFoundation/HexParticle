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


# Ethernet 
ETHER_TYPE_IPV4 = 0x0800


def get_protocol_name(proto_number: int) -> str:
    return IPV4_PROTOCOL_NAMES.get(proto_number, "Unknown Protocol")


__all__ = ['IPV4_PROTOCOLS', 'ETHER_TYPE_IPV4']