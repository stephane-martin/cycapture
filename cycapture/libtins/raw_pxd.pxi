# -*- coding: utf-8 -*-

cdef extern from "tins/rawpdu.h" namespace "Tins" nogil:
    PDUType raw_pdu_flag "Tins::RawPDU::pdu_flag"
    cdef cppclass cppRAW "Tins::RawPDU" (cppPDU):
        #typedef std::vector<uint8_t> payload_type
        cppRAW(const uint8_t *pload, uint32_t size) except +ValueError
        cppRAW(const string &data) except +custom_exception_handler
        void payload(const vector[uint8_t] &pload) except +custom_exception_handler
        const vector[uint8_t] &payload() const
        uint32_t payload_size() const
        T to[T]() except +custom_exception_handler

cdef class RAW(PDU):
    cdef cppRAW* ptr
    cpdef to(self, obj)

cdef factory_raw(cppPDU* ptr, uint8_t* buf, int size, object parent)
