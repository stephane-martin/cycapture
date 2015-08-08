# -*- coding: utf-8 -*-

cdef factory_udp(cppPDU* ptr, uint8_t* buf, int size, object parent):
    if ptr is NULL and buf is NULL:
        return UDP()
    obj = UDP(_raw=True)
    obj.ptr = new cppUDP(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppUDP*> ptr
    obj.base_ptr = <cppPDU*> obj.ptr
    obj.parent = parent
    return obj


cdef class UDP(PDU):
    pdu_flag = PDU.UDP
    pdu_type = PDU.UDP

    def __cinit__(self, dest_src_ports=None, buf=None, _raw=False):
        if _raw:
            return
        elif buf is None and dest_src_ports is None:
            self.ptr = new cppUDP()
        elif buf is not None:
            if PyBytes_Check(buf):
                self.ptr = new cppUDP(<uint8_t*> PyBytes_AS_STRING(buf), <uint32_t> PyBytes_Size(buf))
            elif isinstance(buf, bytearray):
                buf = memoryview(buf)
                self.ptr = new cppUDP(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            elif isinstance(buf, memoryview):
                if buf.itemsize == 1 and buf.ndim == 1:
                    self.ptr = new cppUDP(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
                else:
                    raise ValueError("the memoryview doesn't have the proper format")
            elif isinstance(buf, cy_memoryview):
                if buf.itemsize == 1 and buf.ndim == 1:
                    self.ptr = new cppUDP(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
                else:
                    raise ValueError("the typed memoryview doesn't have the proper format")
            else:
                raise ValueError("don't know what to do with type '%s'" % type(buf))
        elif PyTuple_Check(dest_src_ports) or PyList_Check(dest_src_ports):
            dest, src = dest_src_ports
            if src is None:
                src = 0
            if dest is None:
                dest = 0
            self.ptr = new cppUDP(<uint16_t>int(dest), <uint16_t>int(src))
        else:
            self.ptr = new cppUDP(<uint16_t>int(dest_src_ports))
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

