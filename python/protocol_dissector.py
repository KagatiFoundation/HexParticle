from hex import protocols as protos

from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget, QTextEdit

class ProtocolDissector(QWidget):
    COMMON_PORTS = {53: "DNS", 80: "HTTP", 443: "HTTPS", 67: "DHCP", 68: "DHCP"}

    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.setColumnWidth(0, 200)
        self.layout.addWidget(self.tree)


    def display_packet(self, pwrapper):
        """
        Processes the PacketWrapper (which contains the layers 
        parsed from ProtocolNode_t) and populates the tree.
        """
        self.tree.clear()
        
        for layer in pwrapper.layers:
            if isinstance(layer, protos.EtherHeader):
                self._add_ethernet_layer(layer)
            elif isinstance(layer, protos.ARPHeader):
                self._add_arp_layer(layer)
            elif isinstance(layer, protos.IPV4Header):
                self._add_ipv4_layer(layer)
            elif isinstance(layer, protos.TCPHeader):
                self._add_tcp_layer(layer)
            elif isinstance(layer, protos.UDPHeader):
                self._add_udp_layer(layer)


    def to_mac_str(self, bytes):
        return ":".join(map(hex, bytes)).replace("0x", "")

    
    def to_ip_str(self, octets):
        return ".".join(map(str, octets))

    
    def _add_ethernet_layer(self, ether):
        parent = QTreeWidgetItem(self.tree, ["Ethernet"])
        proto_name = protos.ETHER_TYPE_NAMES.get(ether.type)
        QTreeWidgetItem(parent, ["Source Address", self.to_mac_str(ether.src_mac)])
        QTreeWidgetItem(parent, ["Destination Address", self.to_mac_str(ether.dst_mac)])
        QTreeWidgetItem(parent, ["Type", str(proto_name)])
        QTreeWidgetItem(parent, ["Length", hex(ether.len)])
        parent.setExpanded(False)


    def _add_arp_layer(self, arp):
        arp_type = "Reply" if arp.op == protos.ARP_RESPONSE else "Request"
        parent = QTreeWidgetItem(self.tree, [f"Address Resolution Protocol ({arp_type})"])
        QTreeWidgetItem(parent, ["Hardware Type", str(arp.htype)])

        proto_name = protos.ETHER_TYPE_NAMES.get(arp.ptype)
        QTreeWidgetItem(parent, ["Protocol Type", str(proto_name) + f" ({hex(arp.ptype)})"])
        QTreeWidgetItem(parent, ["Hardware Length", hex(arp.hlen)])
        QTreeWidgetItem(parent, ["Protocol Length", hex(arp.plen)])
        QTreeWidgetItem(parent, ["Opcode", f"{arp_type} ({hex(arp.op)})"])
        QTreeWidgetItem(parent, ["Sender MAC Address", self.to_mac_str(arp.sha)])
        QTreeWidgetItem(parent, ["Sender Protocol Address", self.to_ip_str(arp.spa)])
        QTreeWidgetItem(parent, ["Target MAC Address", self.to_mac_str(arp.tha)])
        QTreeWidgetItem(parent, ["Target Protocol Address", self.to_ip_str(arp.tpa)])
        parent.setExpanded(True)


    def _add_ipv4_layer(self, ipv4):
        parent = QTreeWidgetItem(self.tree, ["Internet Protocol Version 4"])
        QTreeWidgetItem(parent, ["Version/IHL", hex(ipv4.ver_ihl)])
        QTreeWidgetItem(parent, ["Total Length", str(ipv4.len)])
        QTreeWidgetItem(parent, ["Identification", hex(ipv4.id)])
        QTreeWidgetItem(parent, ["TTL", str(ipv4.ttl)])
        QTreeWidgetItem(parent, ["Protocol", str(ipv4.proto)])
        QTreeWidgetItem(parent, ["Source", ".".join(map(str, ipv4.src))])
        QTreeWidgetItem(parent, ["Destination", ".".join(map(str, ipv4.dst))])
        parent.setExpanded(False)


    def _add_tcp_layer(self, tcp):
        parent = QTreeWidgetItem(self.tree, ["Transmission Control Protocol"])
        QTreeWidgetItem(parent, ["Source Port", str(tcp.sport)])

        port_info = ProtocolDissector.COMMON_PORTS.get(tcp.dport, "")
        QTreeWidgetItem(parent, ["Destination Port", f"{tcp.dport} {port_info}"])

        QTreeWidgetItem(parent, ["Sequence Number", str(tcp.seq)])
        QTreeWidgetItem(parent, ["Acknowledgment Number", str(tcp.ack)])
        QTreeWidgetItem(parent, ["Flags", hex(tcp.flags)])
        QTreeWidgetItem(parent, ["Window Size", str(tcp.win)])
        parent.setExpanded(True)

    
    def _add_udp_layer(self, udp):
        parent = QTreeWidgetItem(self.tree, ["User Datagram Protocol"])
        QTreeWidgetItem(parent, ["Source Port", str(udp.sport)])

        port_info = ProtocolDissector.COMMON_PORTS.get(udp.dport, "")
        QTreeWidgetItem(parent, ["Destination Port", f"{udp.dport} {port_info}"])

        QTreeWidgetItem(parent, ["Length", f"{udp.length} bytes"])
        QTreeWidgetItem(parent, ["Checksum", f"0x{udp.cksum:04x}"])
        parent.setExpanded(True)


class HexViewer(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFontFamily("Courier New")
        self.setFontPointSize(10)
        self.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")

    def set_data(self, raw_bytes: bytes):
        if not raw_bytes:
            self.setText("No payload data.")
            return

        hex_dump = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            
            # Address column (0000, 0010, etc)
            address = f"{i:04x}  "
            
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(48)
            
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_dump.append(f"{address}{hex_part}  |{ascii_part}|")

        self.setPlainText("\n".join(hex_dump))