# -*- coding: utf-8 -*-

cdef extern from "tins/sll.h" namespace "Tins" nogil:
    PDUType sll_pdu_flag "Tins::SLL::pdu_flag"

    cppclass cppSLL "Tins::SLL" (cppPDU):
        cppSLL()
        cppSLL(const uint8_t *buf, uint32_t total_sz)

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

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return SLL()
        obj = SLL(_raw=True)
        obj.ptr = new cppSLL(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppSLL*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

