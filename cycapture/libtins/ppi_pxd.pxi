# -*- coding: utf-8 -*-

cdef extern from "tins/ppi.h" namespace "Tins" nogil:
    PDUType ppi_pdu_flag "Tins::PPI::pdu_flag"

    cppclass cppPPI "Tins::PPI" (cppPDU):
        cppPPI(const uint8_t *buf, uint32_t total_sz)
        uint8_t version() const
        uint8_t flags() const
        uint16_t length() const
        uint32_t dlt() const

cdef class PPI(PDU):
    cdef cppPPI* ptr

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            raise ValueError
            # return BootP()
        obj = PPI(_raw=True)
        obj.ptr = new cppPPI(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppPPI*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj
