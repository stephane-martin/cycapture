# -*- coding: utf-8 -*-

cdef extern from "tins/dot1q.h" namespace "Tins" nogil:
    PDUType dot1q_pdu_flag "Tins::Dot1Q::pdu_flag"

    cppclass cppDot1Q "Tins::Dot1Q" (cppPDU):
        cppDot1Q()
        cppDot1Q(small_uint12 tag_id)
        cppDot1Q(small_uint12 tag_id, cpp_bool append_pad)
        cppDot1Q(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        small_uint3 priority() const
        void priority(small_uint3 new_priority)

        small_uint1 cfi() const
        void cfi(small_uint1 new_cfi)

        small_uint12 id() const
        void id(small_uint12 new_id)

        uint16_t payload_type() const
        void payload_type(uint16_t new_type)

        cpp_bool append_padding() const
        void append_padding(cpp_bool value)

cdef class Dot1Q(PDU):
    cdef cppDot1Q* ptr
