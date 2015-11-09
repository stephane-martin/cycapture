# -*- coding: utf-8 -*-

cdef extern from "tins/ppi.h" namespace "Tins" nogil:
    PDUType ppi_pdu_flag "Tins::PPI::pdu_flag"

    cppclass cppPPI "Tins::PPI" (cppPDU):
        cppPPI(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler
        uint8_t version() const
        uint8_t flags() const
        uint16_t length() const
        uint32_t dlt() const

cdef class PPI(PDU):
    cdef cppPPI* ptr

