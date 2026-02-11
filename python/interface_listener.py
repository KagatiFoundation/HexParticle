# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

import json
import typing

from particle import HexParticleSniffer
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton, QLabel)
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


    def register_protocol_cb(self, proto_type: int, cb: typing.Callable):
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
        self.packet_log = QListWidget()
        layout.addWidget(self.packet_log)

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
        self.worker.register_protocol_cb(protos.ETHER_TYPE_IPV4, self.on_ipv4_packet)
        self.worker.start()

    
    def on_ipv4_packet(self, packet):
        payload = packet.get('Payload', {})
        proto = payload.get("Protocol", "?")
        name = payload.get("Protocol Name", "Unknown")

        display_text = f"Proto: {proto} | Name: {name}"
        self.packet_log.addItem(display_text)

        self.packet_log.scrollToBottom()


    def on_tcp_packet(self, packet):
        pass


    def stop_sniffing(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)


    def process_packet(self, packet_str):
        try:
            data = json.loads(packet_str)
            if int(data.get('Payload Type', 0)) == 0x0800:
                payload = data.get('Payload', {})
                proto = payload.get("Protocol", "?")
                name = payload.get("Protocol Name", "Unknown")
                
                display_text = f"Proto: {proto} | Name: {name}"
                self.packet_log.addItem(display_text)
                self.packet_log.scrollToBottom()
        except Exception as e:
            pass