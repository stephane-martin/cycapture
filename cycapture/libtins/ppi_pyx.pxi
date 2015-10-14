# -*- coding: utf-8 -*-

cdef class PPI(PDU):
    pdu_flag = PDU.PPI
    pdu_type = PDU.PPI

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != PPI:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            raise ValueError
            # self.ptr = new cppPKTAP()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppPPI(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppPPI* p = <cppPPI*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    property version:
        def __get__(self):
            return int(self.ptr.version())

    property flags:
        def __get__(self):
            return int(self.ptr.flags())

    property length:
        def __get__(self):
            return int(self.ptr.length())

    property dlt:
        def __get__(self):
            return int(self.ptr.dlt())
