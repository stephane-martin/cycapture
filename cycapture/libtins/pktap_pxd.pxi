# -*- coding: utf-8 -*-

cdef extern from "tins/pktap.h" namespace "Tins" nogil:
    PDUType pktap_pdu_flag "Tins::PKTAP::pdu_flag"

    cppclass cppPKTAP "Tins::PKTAP" (cppPDU):
        cppPKTAP()
        cppPKTAP(const uint8_t* buf, uint32_t total_sz)


cdef class PKTAP(PDU):
    cdef cppPKTAP* ptr

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return PKTAP()
        obj = PKTAP(_raw=True)
        obj.ptr = new cppPKTAP(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppPKTAP*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj
