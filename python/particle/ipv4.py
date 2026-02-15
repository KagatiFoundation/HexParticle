import ctypes

class IPv4(ctypes.Structure):
    _fields_ = [
        ("ver_ihl", ctypes.c_uint8),
        ("dscp_ecn", ctypes.c_uint8),
        ("len", ctypes.c_uint16),
        ("id", ctypes.c_uint16),
        ("flags_off", ctypes.c_uint16),
        ("ttl", ctypes.c_uint8),
        ("proto", ctypes.c_uint8),
        ("chk", ctypes.c_uint16),
        ("src", ctypes.c_uint8 * 4),
        ("dst", ctypes.c_uint8 * 4),
    ]