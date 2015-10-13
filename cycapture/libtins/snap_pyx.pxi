# -*- coding: utf-8 -*-

cdef class SNAP(PDU):
    pdu_flag = PDU.SNAP
    pdu_type = PDU.SNAP

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != SNAP:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppSNAP()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppSNAP(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSNAP* p = <cppSNAP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    property org_code:
        def __get__(self):
            return int(<uint32_t> self.ptr.org_code())
        def __set__(self, value):
            self.ptr.org_code(small_uint24(<uint32_t> int(value)))

    property eth_type:
        def __get__(self):
            return int(self.ptr.eth_type())
        def __set__(self, value):
            self.ptr.eth_type(<uint16_t> int(value))

    property control:
        def __get__(self):
            return int(self.ptr.control())
        def __set__(self, value):
            self.ptr.control(<uint8_t> int(value))

    property dsap:
        def __get__(self):
            return int(self.ptr.dsap())

    property ssap:
        def __get__(self):
            return int(self.ptr.ssap())



