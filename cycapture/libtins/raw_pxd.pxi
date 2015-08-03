# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp.list cimport list as cpp_list
from libcpp.pair cimport pair

cdef extern from "tins/rawpdu.h" namespace "Tins":
    PDUType raw_pdu_flag "Tins::RawPDU::pdu_flag"
    cdef cppclass cppRAW "Tins::RawPDU" (cppPDU):
        #typedef std::vector<uint8_t> payload_type
        cppRAW(const uint8_t *pload, uint32_t size)
        cppRAW(const string &data)
        void payload(const vector[uint8_t] &pload)
        const vector[uint8_t] &payload() const
        uint32_t payload_size() const
        T to[T]() const

cdef class Raw(PDU):
    cdef cppRAW* ptr

cdef factory_raw(cppPDU* ptr, object parent)
cdef make_raw_from_const_uchar_buf(const uint8_t* buf, int size)
cdef make_raw_from_uchar_buf(uint8_t* buf, int size)
cpdef make_raw_from_typed_memoryview(unsigned char[:] data)
