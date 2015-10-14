# -*- coding: utf-8 -*-

cdef class PKTAP(PDU):
    pdu_flag = PDU.PKTAP
    pdu_type = PDU.PKTAP

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != PKTAP:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppPKTAP()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppPKTAP(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppPKTAP* p = <cppPKTAP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass
