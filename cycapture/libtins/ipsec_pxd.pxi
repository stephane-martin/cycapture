# -*- coding: utf-8 -*-

cdef extern from "tins/ipsec.h" namespace "Tins" nogil:
    PDUType ipsecah_pdu_flag "Tins::IPSecAH::pdu_flag"
    PDUType ipsecesp_pdu_flag "Tins::IPSecESP::pdu_flag"

    cppclass cppIPSecAH "Tins::IPSecAH" (cppPDU):
        cppIPSecAH()
        cppIPSecAH(const uint8_t *buf, uint32_t total_sz)

        uint8_t next_header() const
        uint8_t length() const
        uint32_t spi() const
        uint32_t seq_number() const
        const vector[uint8_t] &icv() const

        void next_header(uint8_t new_next_header)
        void length(uint8_t new_length)
        void spi(uint32_t new_spi)
        void seq_number(uint32_t new_seq_number)
        void icv(const vector[uint8_t] &new_icv)

    cppclass cppIPSecESP "Tins::IPSecESP" (cppPDU):
        cppIPSecESP()
        cppIPSecESP(const uint8_t *buf, uint32_t total_sz)

        uint32_t spi() const
        uint32_t seq_number() const

        void spi(uint32_t new_spi)
        void seq_number(uint32_t new_seq_number)

cdef class IPSecAH(PDU):
    cdef cppIPSecAH* ptr

cdef class IPSecESP(PDU):
    cdef cppIPSecESP* ptr

