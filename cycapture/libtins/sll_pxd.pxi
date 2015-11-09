# -*- coding: utf-8 -*-

cdef extern from "tins/sll.h" namespace "Tins" nogil:
    PDUType sll_pdu_flag "Tins::SLL::pdu_flag"

    cppclass cppSLL "Tins::SLL" (cppPDU):
        cppSLL()
        cppSLL(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        uint16_t packet_type() const
        void packet_type(uint16_t new_packet_type)

        uint16_t lladdr_type() const
        void lladdr_type(uint16_t new_lladdr_type)

        uint16_t lladdr_len() const
        void lladdr_len(uint16_t new_lladdr_len)

        cppHWAddress8 address() const
        void address(const cppHWAddress8 &new_address)

        uint16_t protocol() const
        void protocol(uint16_t new_protocol)

cdef class SLL(PDU):
    cdef cppSLL* ptr


