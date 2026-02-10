'''
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>
'''

import sys
import json
from particle import HexParticleSniffer, InterfaceManager
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QListWidget, QPushButton, QLabel)
from PyQt6.QtCore import QThread, pyqtSignal, Qt

class SnifferWorker(QThread):
    packet_received = pyqtSignal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True

    def run(self):
        try:
            sniffer = HexParticleSniffer(self.interface)
            while self.running:
                packet = sniffer.next_packet()
                if packet:
                    self.packet_received.emit(packet)
            sniffer.close()
        except Exception as e:
            print(f"Worker Error: {e}")

    def stop(self):
        self.running = False

class ParticleApp(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
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

        layout.addWidget(QLabel("Select Interface:"))
        self.if_list = QListWidget()
        self.if_list.setFixedHeight(100)
        layout.addWidget(self.if_list)

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

        self.load_interfaces()

    def load_interfaces(self):
        try:
            manager = InterfaceManager()
            names = manager.get_all_interface_names()
            self.if_list.addItems(names)
        except Exception as e:
            self.packet_log.addItem(f"Error loading interfaces: {e}")

    def start_sniffing(self):
        selected = self.if_list.currentItem()
        if not selected: return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self.worker = SnifferWorker(selected.text())
        self.worker.packet_received.connect(self.process_packet)
        self.worker.start()

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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ParticleApp()
    window.show()
    sys.exit(app.exec())