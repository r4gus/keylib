cimport uhid
from libc.stdlib cimport malloc, free
from libc.stdint cimport uintptr_t

cdef extern from "keylib/uhid.h":
    int uhid_open()
    void uhid_close(int fd)
    int uhid_read_packet(int fd, char* out)
    int uhid_write_packet(int fd, char* inp, uintptr_t l)

def open():
    """
    Open a virtual USB HID device that presents itself as FIDO2 authenticator
    
    Returns:
    A struct wrapping the file descriptor of the hid file
    """
    cdef uhid.Uhid obj
    obj.fd = uhid_open()
    return obj

def close(obj):
    uhid_close(obj['fd'])

def read_packet(obj) -> bytes:
    cdef char* buffer = <char*>malloc(256)
    if buffer is NULL:
        raise MemoryError("Failed to allocate memory for uhid packet")

    try:
        l = uhid_read_packet(obj['fd'], buffer)
        result = bytes(buffer[:l])
    finally:
        free(buffer)
    
    return result

def write_packet(obj,bytes data):
    uhid_write_packet(obj['fd'], data, len(data))

