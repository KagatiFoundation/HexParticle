# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

from hex import protocols as protos, mac_to_str

class EthernetDissectorComponent:
    @staticmethod
    def dissect(parent_node, ether_header):
        parent = widgets.QTreeWidgetItem(parent_node, ["Ethernet"])
        proto_name = protos.ETHER_TYPE_NAMES.get(ether_header.type)
        widgets.QTreeWidgetItem(parent, ["Source Address", mac_to_str(ether_header.src_mac)])
        widgets.QTreeWidgetItem(parent, ["Destination Address", mac_to_str(ether_header.dst_mac)])
        widgets.QTreeWidgetItem(parent, ["Type", str(proto_name)])
        widgets.QTreeWidgetItem(parent, ["Length", hex(ether_header.len)])
        parent.setExpanded(False)