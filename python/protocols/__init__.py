IPV4_PROTOCOLS = {
    0x01: "ICMP(Internet Control Message Protocol)",
    0x02: "IGMP(Internet Group Management Protocol)",
    0x06: "TCP(Transmission Control Protocol)",
    0x11: "UDP(User Datagram Protocol)",
    0x2B: "IPv6-Route(Routing Header for IPv6)",
    0x20: "DSR(Dynamic Source Routing Protocol)",
    0x35: "SwIPe(Swipe IP Security Protocol)",
    0x38: "TLSP(Transport Layer Security Protocol)",
    0x39: "SKIP(Simple Key Management for IP)",
    0x40: "SAT-EXPAK(SATNET and Backroom EXPAK)",
    0x58: "EIGRP(Enhanced Interior Gateway Routing Protocol)",
    0x59: "OSPF(Open Shorted Path First)",
    0x73: "L2TP(Layer 2 Tunneling Protocol version 3)",
}

# Ethernet 
ETHER_TYPE_IPV4 = 0x0800

def get_protocol_name(proto_number: int) -> str:
    return IPV4_PROTOCOLS.get(proto_number, "Unknown Protocol")


__all__ = ['IPV4_PROTOCOLS', 'get_protocol_name']