# -*- coding: utf-8 -*-

cdef extern from "tins/pktap.h" namespace "Tins" nogil:
    PDUType pktap_pdu_flag "Tins::PKTAP::pdu_flag"

    cppclass cppPKTAP "Tins::PKTAP" (cppPDU):
        # cppPKTAP()
        cppPKTAP(const uint8_t* buf, uint32_t total_sz) except +custom_exception_handler


cdef class PKTAP(PDU):
    cdef cppPKTAP* ptr

