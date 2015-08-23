# -*- coding: utf-8 -*-

cdef class UDP(PDU):
    pdu_flag = PDU.UDP
    pdu_type = PDU.UDP

    def __cinit__(self, dest_src_ports=None, buf=None, _raw=False):
        cdef uint8_t* buf_addr
        cdef uint32_t size

        if _raw:
            return
        elif buf is None and dest_src_ports is None:
            self.ptr = new cppUDP()
        elif buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppUDP(buf_addr, size)
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

