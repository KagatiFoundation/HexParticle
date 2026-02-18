from hex import protocols as protos

from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

class ProtocolDissector(QWidget):
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
            elif isinstance(layer, protos.IPV4Header):
                self._add_ipv4_layer(layer)
            elif isinstance(layer, protos.TCPHeader):
                self._add_tcp_layer(layer)

    
    def _add_ethernet_layer(self, ether):
        parent = QTreeWidgetItem(self.tree, ["Ethernet"])
        proto_name = protos.ETHER_TYPE_NAMES.get(ether.type)
        QTreeWidgetItem(parent, ["Source Address", ":".join(map(hex, ether.src_mac)).replace("0x", "")])
        QTreeWidgetItem(parent, ["Destination Address", ":".join(map(hex, ether.dst_mac)).replace("0x", "")])
        QTreeWidgetItem(parent, ["Type", str(proto_name)])
        QTreeWidgetItem(parent, ["Length", hex(ether.len)])
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
        parent.setExpanded(True)


    def _add_tcp_layer(self, tcp):
        parent = QTreeWidgetItem(self.tree, ["Transmission Control Protocol"])
        QTreeWidgetItem(parent, ["Source Port", str(tcp.sport)])
        QTreeWidgetItem(parent, ["Destination Port", str(tcp.dport)])
        QTreeWidgetItem(parent, ["Sequence Number", str(tcp.seq)])
        QTreeWidgetItem(parent, ["Acknowledgment Number", str(tcp.ack)])
        QTreeWidgetItem(parent, ["Flags", hex(tcp.flags)])
        QTreeWidgetItem(parent, ["Window Size", str(tcp.win)])
        parent.setExpanded(True)