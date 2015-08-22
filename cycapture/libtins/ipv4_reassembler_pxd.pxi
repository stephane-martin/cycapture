# -*- coding: utf-8 -*-

cdef extern from "tins/ip_reassembler.h" namespace "Tins" nogil:

    ctypedef enum packet_status "Tins::IPv4Reassembler::packet_status":
        TINS_NOT_FRAGMENTED "Tins::IPv4Reassembler::NOT_FRAGMENTED",
        TINS_FRAGMENTED "Tins::IPv4Reassembler::FRAGMENTED",
        TINS_REASSEMBLED "Tins::IPv4Reassembler::REASSEMBLED"

    ctypedef enum overlapping_technique "Tins::IPv4Reassembler::overlapping_technique":
        TINS_NONE "Tins::IPv4Reassembler::NONE"

    cdef cppclass IPv4Reassembler:
        IPv4Reassembler()
        IPv4Reassembler(overlapping_technique)
        packet_status process(cppPDU &pdu)
        #void clear_streams()
        #void remove_stream(uint16_t ident, IPv4Address addr1, IPv4Address addr2)


cdef class IPReassembler(object):
    cdef object py_callback
    cdef IPv4Reassembler* assembler
    cpdef feed(self, PDU pdu)


