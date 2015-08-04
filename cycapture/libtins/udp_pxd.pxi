# -*- coding: utf-8 -*-
# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t
from libcpp.vector cimport vector
from libcpp.list cimport list as cpp_list
from libcpp.pair cimport pair

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

cdef factory_udp(cppPDU* ptr, object parent)
cdef make_UDP_from_const_uchar_buf(const uint8_t* buf, int size)
cdef make_UDP_from_uchar_buf(uint8_t* buf, int size)
cpdef make_UDP_from_typed_memoryview(unsigned char[:] data)
