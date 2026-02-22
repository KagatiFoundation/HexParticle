# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

from hex import protocols as protos
import dissectors

from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

class ProtocolDissector(QWidget):
    COMMON_PORTS = {53: "DNS", 80: "HTTP", 443: "HTTPS", 67: "DHCP", 68: "DHCP"}

    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value"])
        self.tree.setColumnWidth(0, 200)
        self.layout.addWidget(self.tree)

        self.dissection_handlers = {
            protos.TCPHeader: dissectors.TCPDissectorComponent.dissect,
            protos.IPV4Header: dissectors.IPV4DissectorComponent.dissect,
            protos.ARPHeader: dissectors.ARPDissectorComponent.dissect,
            protos.EtherHeader: dissectors.EthernetDissectorComponent.dissect
        }


    def display_packet(self, pwrapper):
        """
        Processes the PacketWrapper (which contains the layers 
        parsed from ProtocolNode_t) and populates the tree.
        """
        self.tree.clear()
        
        for layer in pwrapper.layers:
            dissec_handler = self.dissection_handlers.get(type(layer))
            if dissec_handler:
                dissec_handler(self.tree, layer)

            if isinstance(layer, protos.UDPHeader):
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

    
    def _add_udp_layer(self, udp):
        parent = QTreeWidgetItem(self.tree, ["User Datagram Protocol"])
        QTreeWidgetItem(parent, ["Source Port", str(udp.sport)])

        port_info = ProtocolDissector.COMMON_PORTS.get(udp.dport, "")
        QTreeWidgetItem(parent, ["Destination Port", f"{udp.dport} {port_info}"])

        QTreeWidgetItem(parent, ["Length", f"{udp.length} bytes"])
        QTreeWidgetItem(parent, ["Checksum", f"0x{udp.cksum:04x}"])
        parent.setExpanded(True)