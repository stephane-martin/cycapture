# -*- coding: utf-8 -*-

cdef extern from "tins/udp.h" namespace "Tins" nogil:
    PDUType udp_pdu_flag "Tins::UDP::pdu_flag"

    cdef cppclass cppUDP "Tins::UDP" (cppPDU):
        cppUDP()
        cppUDP(uint16_t dport)
        cppUDP(uint16_t dport, uint16_t sport)
        cppUDP(const uint8_t *buf, uint32_t total_sz)
        uint16_t dport() const
        void dport(uint16_t new_dport)
        uint16_t sport() const
        void sport(uint16_t new_sport)
        uint16_t length() const
        void length(uint16_t new_len)
        uint16_t checksum() const

        cpp_bool matches_response(const uint8_t *ptr, uint32_t total_sz) const

cdef class UDP(PDU):
    cdef cppUDP* ptr

cdef factory_udp(cppPDU* ptr, uint8_t* buf, int size, object parent)
