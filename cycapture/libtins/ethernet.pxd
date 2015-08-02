# -*- coding: utf-8 -*-
# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t
from libcpp.vector cimport vector

cdef extern from "tins/ethernetII.h" namespace "Tins":
    # noinspection PyUnresolvedReferences
    PDUType ethII_pdu_flag "Tins::EthernetII::pdu_flag"
    cppHWAddress6 ethII_BROADCAST "Tins::EthernetII::BROADCAST"

    cdef cppclass cppEthernetII "Tins::EthernetII" (cppPDU):
        cppEthernetII()
        cppEthernetII(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppEthernetII(const unsigned char *buf, uint32_t total_sz)
        cppHWAddress6 dst_addr() const
        cppHWAddress6 src_addr() const
        uint16_t payload_type() const
        void dst_addr(const cppHWAddress6 &new_dst_addr)
        void src_addr(const cppHWAddress6 &new_src_addr)
        void payload_type(uint16_t new_payload_type)
        #uint32_t header_size() const
        #uint32_t trailer_size() const
        #PDUType pdu_type() const
        #cppEthernetII *clone() const
        #pointer find_pdu[T]()


cdef class EthernetII(PDU):
    cdef cppEthernetII* ptr
