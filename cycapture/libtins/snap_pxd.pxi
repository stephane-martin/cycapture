# -*- coding: utf-8 -*-

cdef extern from "tins/snap.h" namespace "Tins" nogil:
    PDUType snap_pdu_flag "Tins::SNAP::pdu_flag"

    cppclass cppSNAP "Tins::SNAP" (cppPDU):
        cppSNAP()
        cppSNAP(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        void control(uint8_t new_control)
        void org_code(small_uint24 new_org)
        void eth_type(uint16_t new_eth)
        uint8_t dsap() const
        uint8_t ssap() const
        uint8_t control() const

        small_uint24 org_code() const
        uint16_t eth_type() const

cdef class SNAP(PDU):
    cdef cppSNAP* ptr

