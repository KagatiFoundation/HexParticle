# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

import ctypes
import json

ETHER_IPV4 = 0x0800

lib_particle = ctypes.CDLL("../lib/libparticle.so")

'''
These functions are for capturing and managing packets
'''
lib_particle.particle_open.argtypes = [ctypes.c_char_p]
lib_particle.particle_open.restype = ctypes.c_void_p

lib_particle.particle_next.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
lib_particle.particle_next.restype = ctypes.c_int

lib_particle.particle_close.argtypes = [ctypes.c_void_p]
lib_particle.particle_close.restype = None

'''
Interface related functions
'''
lib_particle.get_all_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_int)]
lib_particle.get_all_interfaces_names.restype = ctypes.POINTER(ctypes.c_char_p)

lib_particle.free_interfaces_names.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
lib_particle.free_interfaces_names.restype = None

# buffer size for a standard packet
OUT_BUF_SIZE = 4096

class HexParticleSniffer:
    def __init__(self, device: str):
        self.handle = lib_particle.particle_open(device.encode('utf-8'))
        if not self.handle:
            raise RuntimeError(f"Failed to open device {device}")

    def next_packet(self) -> dict:
        buf = ctypes.create_string_buffer(OUT_BUF_SIZE)
        result = lib_particle.particle_next(self.handle, buf, OUT_BUF_SIZE)
        if result == 0:
            return buf.value.decode('utf-8')
        else:
            return None

    def close(self):
        if self.handle:
            lib_particle.particle_close(self.handle)
            self.handle = None

    def __del__(self):
        self.close()


class InterfaceManager:
    def get_all_interface_names(self):
        self.count = ctypes.c_int()
        self.interfaces = lib_particle.get_all_interfaces_names(ctypes.byref(self.count))
        if not self.interfaces:
            raise RuntimeError(f"Failed to get interface names")
        return [self.interfaces[i].decode("UTF-8") for i in range(self.count.value)]

    def __del__(self):
        lib_particle.free_interfaces_names(self.interfaces, self.count)


if __name__ == "__main__":
    sniffer = HexParticleSniffer("en0") # on my macOS machine
    for _ in range(100):
        packet = sniffer.next_packet()
        if packet is not None:
            try:
                packet_json = json.loads(packet)
                if int(packet_json['Payload Type']) == ETHER_IPV4:
                    payload = packet_json['Payload']
                    protocol = payload.get("Protocol")
                    protocol_name = payload.get("Protocol Name")
                    print(f"{protocol} = {protocol_name}")
            except json.JSONDecodeError as err:
                print(err)