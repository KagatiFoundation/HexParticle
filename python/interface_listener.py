# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

import json
import typing

from particle import HexParticleSniffer
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                                    QTableWidget, QTableWidgetItem, QPushButton, QLabel)
from PyQt6.QtCore import QThread, pyqtSignal

import protocols as protos

class HexParticleWorker(QThread):
    packet_received = pyqtSignal(dict)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True
        self.sniffer = HexParticleSniffer(self.interface)


    def run(self):
        try:
            while self.running:
                packet = self.sniffer.next_packet()
                if packet:
                    self.packet_received.emit(packet)
            self.sniffer.close()
        except Exception as e:
            print(f"Worker Error: {e}")


    def register_ethertype_packet_cb(self, proto_type: int, cb: typing.Callable):
        self.sniffer.register(proto_type, cb)


    def stop(self):
        self.running = False


class InterfaceListener(QWidget):
    def __init__(self, interface: str):
        super().__init__()
        self.worker = None
        self.interface = interface
        self.init_ui()


    def init_ui(self):
        self.setWindowTitle("HexParticle Sniffer")
        self.resize(600, 500)
        self.setStyleSheet("""
            QWidget { background-color: #1a1a1a; color: #ececec; font-family: 'Segoe UI', sans-serif; }
            QListWidget { background-color: #2d2d2d; border: 1px solid #3f3f3f; border-radius: 4px; padding: 5px; }
            QPushButton { background-color: #0e639c; color: white; padding: 8px; border: none; border-radius: 4px; }
            QPushButton:hover { background-color: #1177bb; }
            QPushButton:disabled { background-color: #444; color: #888; }
        """)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Live Packets (IPv4 Protocol Mapping):"))
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(
            ["Source", "Destination", "Protocol", "Length", "Info"]
        )
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setAlternatingRowColors(True)
        layout.addWidget(self.packet_table)

        ctrl_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        
        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        
        ctrl_layout.addWidget(self.start_btn)
        ctrl_layout.addWidget(self.stop_btn)
        layout.addLayout(ctrl_layout)


    def start_sniffing(self):
        if not self.interface: return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self.worker = HexParticleWorker(self.interface)
        self.worker.register_ethertype_packet_cb(protos.ETHER_TYPE_IPV4, self.on_ipv4_packet)
        self.worker.start()


    def add_packet_row(self, src, dst, proto, length, info):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        self.packet_table.setItem(row, 0, QTableWidgetItem(str(src)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(str(dst)))
        self.packet_table.setItem(row, 2, QTableWidgetItem(str(proto)))
        self.packet_table.setItem(row, 3, QTableWidgetItem(str(length)))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(info)))

        self.packet_table.scrollToBottom()

    
    def on_ipv4_packet(self, packet):
        eth_packet = packet['Payload']
        ipv4 = eth_packet['Payload']
        payload_type = ipv4['Payload Type']

        if payload_type == protos.IPV4_TCP:
            return self.on_tcp_packet(packet)
        elif payload_type == protos.IPV4_UDP:
            return self.on_udp_packet(packet)
        elif payload_type == protos.IPV4_ICMP:
            pass


    def on_tcp_packet(self, packet):
        source = packet['Source']
        destination = packet['Destination']
        protocol = "TCP"
        length = packet['Length']
        info = 'A TCP Packet'

        self.add_packet_row(source, destination, protocol, length, info)


    def on_udp_packet(self, packet):
        self.packet_log.scrollToBottom()


    def stop_sniffing(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)