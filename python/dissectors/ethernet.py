# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import PyQt6.QtWidgets as widgets

from hex import protocols as protos, mac_to_str

class EthernetDissectorComponent:
    @staticmethod
    def dissect(parent_node, ether_header):
        ether_item = widgets.QTreeWidgetItem(parent_node, ["Ethernet"])
        proto_name = protos.ETHER_TYPE_NAMES.get(ether_header.type)
        widgets.QTreeWidgetItem(ether_item, ["Source Address", mac_to_str(ether_header.src_mac)])
        widgets.QTreeWidgetItem(ether_item, ["Destination Address", mac_to_str(ether_header.dst_mac)])
        widgets.QTreeWidgetItem(ether_item, ["Type", str(proto_name)])
        widgets.QTreeWidgetItem(ether_item, ["Length", hex(ether_header.len)])
        ether_item.setExpanded(False)