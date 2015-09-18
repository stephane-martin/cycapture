# -*- coding: utf-8 -*-

cdef extern from "tins/icmp.h" namespace "Tins" nogil:
    PDUType icmp_pdu_flag "Tins::ICMP::pdu_flag"

    ctypedef enum ICMP_Flags "Tins::ICMP::Flags":
        ICMP_ECHO_REPLY "Tins::ICMP::ECHO_REPLY",
        ICMP_DEST_UNREACHABLE "Tins::ICMP::DEST_UNREACHABLE",
        ICMP_SOURCE_QUENCH "Tins::ICMP::SOURCE_QUENCH",
        ICMP_REDIRECT "Tins::ICMP::REDIRECT",
        ICMP_ECHO_REQUEST "Tins::ICMP::ECHO_REQUEST",
        ICMP_TIME_EXCEEDED "Tins::ICMP::TIME_EXCEEDED",
        ICMP_PARAM_PROBLEM "Tins::ICMP::PARAM_PROBLEM",
        ICMP_TIMESTAMP_REQUEST "Tins::ICMP::TIMESTAMP_REQUEST",
        ICMP_TIMESTAMP_REPLY "Tins::ICMP::TIMESTAMP_REPLY",
        ICMP_INFO_REQUEST "Tins::ICMP::INFO_REQUEST",
        ICMP_INFO_REPLY "Tins::ICMP::INFO_REPLY",
        ICMP_ADDRESS_MASK_REQUEST "Tins::ICMP::ADDRESS_MASK_REQUEST",
        ICMP_ADDRESS_MASK_REPLY "Tins::ICMP::ADDRESS_MASK_REPLY"

    cdef cppclass cppICMP "Tins::ICMP" (cppPDU):
        cppICMP()
        cppICMP(ICMP_Flags flag)
        cppICMP(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        uint16_t checksum() const

        uint8_t code() const
        void code(uint8_t new_code)

        ICMP_Flags get_type "type" () const
        void set_type "type" (ICMP_Flags t)

        uint16_t ident "id" () const
        void ident "id" (uint16_t new_id)

        uint16_t sequence() const
        void sequence(uint16_t new_seq)

        cppIPv4Address gateway() const
        void gateway(cppIPv4Address new_gw)

        uint16_t mtu() const
        void mtu(uint16_t new_mtu)

        uint8_t pointer() const
        void pointer(uint8_t new_pointer)

        uint32_t original_timestamp() const
        void original_timestamp(uint32_t new_timestamp)

        uint32_t receive_timestamp() const
        void receive_timestamp(uint32_t new_timestamp)

        uint32_t transmit_timestamp() const
        void transmit_timestamp(uint32_t new_timestamp)

        cppIPv4Address address_mask() const
        void address_mask(cppIPv4Address new_mask)

        void set_echo_request(uint16_t ident, uint16_t seq)
        void set_echo_reply(uint16_t ident, uint16_t seq)
        void set_info_request(uint16_t ident, uint16_t seq)
        void set_info_reply(uint16_t ident, uint16_t seq)
        void set_dest_unreachable()
        void set_time_exceeded()
        void set_time_exceeded(cpp_bool ttl_exceeded)
        void set_param_problem()
        void set_param_problem(cpp_bool set_pointer)
        void set_param_problem(cpp_bool set_pointer, uint8_t bad_octet)
        void set_source_quench()
        void set_redirect(uint8_t icode, cppIPv4Address address)

cdef class ICMP(PDU):
    cdef cppICMP* ptr

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return ICMP()
        obj = ICMP(_raw=True)
        obj.ptr = new cppICMP(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppICMP*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

    cpdef set_dest_unreachable(self)
    cpdef set_source_quench(self)
    cpdef set_time_exceeded(self, flag=?)
    cpdef set_param_problem(self, set_pointer=?, int bad_octet=?)
    cpdef set_echo_request(self, int ident, int seq)
    cpdef set_echo_reply(self, int ident, int seq)
    cpdef set_info_request(self, int ident, int seq)
    cpdef set_info_reply(self, int ident, int seq)
    cpdef set_redirect(self, int code, address)
