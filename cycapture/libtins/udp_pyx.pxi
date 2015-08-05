# -*- coding: utf-8 -*-

cdef factory_udp(cppPDU* ptr, object parent):
    if ptr == NULL:
        raise ValueError("Can't make an IP object from a NULL pointer")
    obj = UDP(_raw=True)
    obj.base_ptr = ptr
    obj.ptr = <cppUDP*> ptr
    obj.parent = parent
    return obj


cdef class UDP(PDU):
    def __cinit__(self, dest_src_ports=None, buf=None, _raw=False):
        if _raw:
            return
        elif buf is None and dest_src_ports is None:
            self.ptr = new cppUDP()
        elif buf is not None:
            # construct from a buffer
            if isinstance(buf, bytes):
                self.ptr = new cppUDP(<uint8_t*> buf, <uint32_t> len(buf))
            elif isinstance(buf, bytearray):
                self.ptr = new cppUDP(<uint8_t*> buf, <uint32_t> len(buf))
            elif isinstance(buf, memoryview):
                # todo: check that buf has the right shape, etc
                self.ptr = new cppUDP(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            elif isinstance(buf, cy_memoryview):
                # todo: check that buf has the right shape, etc
                self.ptr = new cppUDP(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
            else:
                raise ValueError("don't know what to do with type '%s'" % type(buf))
        elif isinstance(dest_src_ports, tuple) or isinstance(dest_src_ports, list):
            dest, src = dest_src_ports
            if src is None:
                src = 0
            if dest is None:
                dest = 0
            src = int(src)
            dest = int(dest)
            self.ptr = new cppUDP(<uint16_t>dest, <uint16_t>src)
        else:
            src = 0
            dest = int(dest_src_ports)
            self.ptr = new cppUDP(<uint16_t>dest, <uint16_t>src)
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dest_src_ports=None, buf=None, _raw=False):
        pass

    property sport:
        def __get__(self):
            return int(self.ptr.sport())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.sport(<uint16_t> int(value))

    property dport:
        def __get__(self):
            return int(self.ptr.dport())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.dport(<uint16_t> int(value))

    property length:
        def __get__(self):
            return int(self.ptr.length())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.length(<uint16_t> int(value))

    property checksum:
        def __get__(self):
            return int(self.ptr.checksum())


cdef make_UDP_from_const_uchar_buf(const uint8_t* buf, int size):
    if size == 0 or buf is NULL:
        return UDP()
    return UDP(buf=make_mview_from_const_uchar_buf(buf, size))

cdef make_UDP_from_uchar_buf(uint8_t* buf, int size):
    if size == 0 or buf is NULL:
        return UDP()
    return TCP(buf=make_mview_from_uchar_buf(buf, size))

cpdef make_UDP_from_typed_memoryview(unsigned char[:] data):
    if data is None or len(data) == 0:
        return UDP()
    return UDP(buf=<cy_memoryview> data)
