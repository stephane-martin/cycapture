# -*- coding: utf-8 -*-

cdef class SLL(PDU):
    """
    Linux cooked-mode capture (SLL) PDU
    """
    pdu_flag = PDU.SLL
    pdu_type = PDU.SLL

    def __cinit__(self, _raw=False):
        if _raw:
            return
        if type(self) != SLL:
            return

        self.ptr = new cppSLL()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSLL* p = <cppSLL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    property packet_type:
        """
        Packet Type field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.packet_type())
        def __set__(self, value):
            self.ptr.packet_type(<uint16_t> int(value))

    property lladdr_type:
        """
        LLADDR Type field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.lladdr_type())
        def __set__(self, value):
            self.ptr.lladdr_type(<uint16_t> int(value))

    property lladdr_len:
        """
        LLADDR Length field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.lladdr_len())
        def __set__(self, value):
            self.ptr.lladdr_len(<uint16_t> int(value))

    property protocol:
        """
        Protocol field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.protocol())
        def __set__(self, value):
            self.ptr.protocol(<uint16_t> int(value))

    property address:
        """
        Address field (read-write, `bytes` like ``b"00:01:02:03:04:05:06:07"``)
        """
        def __get__(self):
            return <bytes> (self.ptr.address().to_string())
        def __set__(self, value):
            cdef string v = bytes(value)
            self.ptr.address(cppHWAddress8(v))

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppSLL(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppSLL*> ptr
