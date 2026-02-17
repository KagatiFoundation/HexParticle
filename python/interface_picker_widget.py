# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QListWidget, QListWidgetItem, QLabel)
from hex.lib_wrapper import InterfaceManager
from interface_listener import InterfaceListener

class InterfacePicker(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.active_listeners = []


    def init_ui(self):
        self.setWindowTitle("HexParticle Sniffer")
        self.resize(400, 300) 
        
        self.setStyleSheet("""
            QWidget { 
                background-color: #121212; 
                color: #e0e0e0; 
                font-family: 'Segoe UI', Tahoma, sans-serif; 
            }

            QListWidget { 
                background-color: #1e1e1e; 
                border: 1px solid #333333; 
                border-radius: 6px; 
                outline: none;
            }

            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #2a2a2a;
                border-radius: 4px;
                margin: 2px 5px;
            }

            QListWidget::item:hover {
                background-color: #2a2a2a;
            }

            QListWidget::item:selected {
                background-color: #0e639c;
                color: white;
            }

            QLabel#Header {
                font-size: 18px;
                font-weight: bold;
                color: #569cd6;
                margin-bottom: 5px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        header = QLabel("Welcome to HexParticle")
        header.setObjectName("Header")
        layout.addWidget(header)
        
        layout.addWidget(QLabel("Select an interface to start analysis:"))
        
        self.interface_list = QListWidget()
        layout.addWidget(self.interface_list)

        self.load_interfaces()


    def load_interfaces(self):
        try:
            manager = InterfaceManager()
            if_names = manager.get_all_interface_names()
            
            self.interface_list.addItems(if_names)
            self.interface_list.itemDoubleClicked.connect(self.handle_interface_selection)

        except Exception as e:
            self.interface_list.addItem(f"Error: {e}")


    def handle_interface_selection(self, item: QListWidgetItem):
        if not item: return

        if not hasattr(self, 'active_listeners'):
            self.active_listeners = []

        interface_name = item.text()
        if_listener = InterfaceListener(interface=interface_name)
        
        self.active_listeners.append(if_listener)
        if_listener.show()