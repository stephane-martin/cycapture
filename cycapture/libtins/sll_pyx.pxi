# -*- coding: utf-8 -*-

cdef class SLL(PDU):
    pdu_flag = PDU.SLL
    pdu_type = PDU.SLL

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != SLL:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppSLL()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppSLL(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSLL* p = <cppSLL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    property packet_type:
        def __get__(self):
            return int(self.ptr.packet_type())
        def __set__(self, value):
            self.ptr.packet_type(<uint16_t> int(value))

    property lladdr_type:
        def __get__(self):
            return int(self.ptr.lladdr_type())
        def __set__(self, value):
            self.ptr.lladdr_type(<uint16_t> int(value))

    property lladdr_len:
        def __get__(self):
            return int(self.ptr.lladdr_len())
        def __set__(self, value):
            self.ptr.lladdr_len(<uint16_t> int(value))

    property protocol:
        def __get__(self):
            return int(self.ptr.protocol())
        def __set__(self, value):
            self.ptr.protocol(<uint16_t> int(value))

    property address:
        def __get__(self):
            return <bytes> (self.ptr.address().to_string())
        def __set__(self, value):
            cdef string v = bytes(value)
            self.ptr.address(cppHWAddress8(v))
