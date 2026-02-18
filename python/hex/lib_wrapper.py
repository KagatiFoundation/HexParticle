# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

import ctypes
import typing

from . import protocols
# import protocols


class HexInstance(ctypes.Structure):
    _fields_ = [
        ("handle", ctypes.c_void_p)
    ]


lib_hexp = ctypes.CDLL("../lib/libhexp.so")

'''
These functions are for capturing and managing packets
'''
lib_hexp.create_hex_instance.argtypes = [ctypes.c_char_p]
lib_hexp.create_hex_instance.restype = HexInstance

lib_hexp.read_next_packet.argtypes = [ctypes.POINTER(HexInstance)]
lib_hexp.read_next_packet.restype = ctypes.POINTER(protocols.ProtocolNode)

lib_hexp.free_hex_instance.argtypes = [ctypes.POINTER(HexInstance)]
lib_hexp.free_hex_instance.restype = None

'''
Interface related functions
'''
lib_hexp.get_all_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_int)]
lib_hexp.get_all_interfaces_names.restype = ctypes.POINTER(ctypes.c_char_p)

lib_hexp.free_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
lib_hexp.free_interfaces_names.restype = None

# free the packet
lib_hexp.free_protocol_node.argtypes = [ctypes.POINTER(protocols.ProtocolNode)]
lib_hexp.free_protocol_node.restype = None


class InterfaceManager:
    def get_all_interface_names(self):
        self.count = ctypes.c_int()
        self.interfaces = lib_hexp.get_all_interfaces_names(ctypes.byref(self.count))
        if not self.interfaces:
            raise RuntimeError(f"Failed to get interface names")
        return [self.interfaces[i].decode("UTF-8") for i in range(self.count.value)]


    def __del__(self):
        lib_hexp.free_interfaces_names(self.interfaces, self.count)


class PacketWrapper:
    TYPE_MAP = {
        protocols.ProtocolType.ETH:     protocols.EtherHeader,
        protocols.ProtocolType.IPV4:    protocols.IPV4Header,
        protocols.ProtocolType.ARP:     protocols.ARPHeader,
        protocols.ProtocolType.TCP:     protocols.TCPHeader,
        protocols.ProtocolType.UDP:     protocols.UDPHeader,
    }
    
    def __init__(self, head_node_ptr):
        self.layers = []
        current = head_node_ptr
        
        while current:
            node = current.contents
            layer_data = self._cast_header(node)
            
            if layer_data is not None:
                self.layers.append(layer_data)

            current = node.next


    def _cast_header(self, node):
        header_class = PacketWrapper.TYPE_MAP.get(node.type)
    
        if not header_class:
            print(f"Unknown protocol type: {node.type}")
            return None
        
        if not node.hdr:
            print(f"Error: Node type {node.type} has a NULL header pointer!")
            return None

        ptr = ctypes.cast(node.hdr, ctypes.POINTER(header_class))
        return header_class.from_buffer_copy(ptr.contents)


    def __repr__(self):
        return " -> ".join([type(l).__name__ for l in self.layers])


class HexParticle():
    """
    A high-level packet sniffing interface for the HexParticle C library.
    """

    def __init__(self, device: str):
        """
        Initializes the sniffer on the specified network interface.

        Args:
            device (str): Name of the network interface (e.g., 'eth0', 'wlan0').
        """
        self.handle: HexInstance = lib_hexp.create_hex_instance(device.encode('utf-8'))
        if not self.handle:
            raise RuntimeError(f"Failed to open device {device}")
        
        self._callbacks: typing.Dict[int, typing.List[typing.Callable[[dict], None]]] = {}


    def next_packet(self) -> PacketWrapper:
        node = lib_hexp.read_next_packet(self.handle)
        if not node:
            return None
    
        pwrapper = PacketWrapper(node)
        
        # free the node
        lib_hexp.free_protocol_node(node)

        return pwrapper


    def close(self):
        if self.handle:
            lib_hexp.free_hex_instance(self.handle)
            self.handle = None


    def __del__(self):
        self.close()


if __name__ == "__main__":
    hex = HexParticle("en0")
    while True:
        packet = hex.next_packet()