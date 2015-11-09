# -*- coding: utf-8 -*-

cdef class PKTAP(PDU):
    pdu_flag = PDU.PKTAP
    pdu_type = PDU.PKTAP

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != PKTAP:
            return

        # todo: self.ptr = new cppPKTAP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppPKTAP* p = <cppPKTAP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppPKTAP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppPKTAP*> ptr

