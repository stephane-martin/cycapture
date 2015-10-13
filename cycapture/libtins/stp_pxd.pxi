# -*- coding: utf-8 -*-

cdef extern from "tins/stp.h" namespace "Tins" nogil:
    PDUType stp_pdu_flag "Tins::STP::pdu_flag"

    # The type used to store the BPDU identifiers
    cppclass bpdu_id_type "Tins::STP::bpdu_id_type":
        small_uint4 priority
        small_uint12 ext_id
        cppHWAddress6 id

        bpdu_id_type()
        bpdu_id_type(small_uint4 priority)
        bpdu_id_type(small_uint4 priority, small_uint12 ext_id)
        bpdu_id_type(small_uint4 priority, small_uint12 ext_id, const cppHWAddress6& ident)

    cppclass cppSTP "Tins::STP" (cppPDU):
        cppSTP()
        cppSTP(const uint8_t *buf, uint32_t total_sz)

        uint16_t proto_id() const
        void proto_id(uint16_t new_proto_id)

        uint8_t proto_version() const
        void proto_version(uint8_t new_proto_version)

        uint8_t bpdu_type() const
        void bpdu_type(uint8_t new_bpdu_type)

        uint8_t bpdu_flags() const
        void bpdu_flags(uint8_t new_bpdu_flags)

        uint32_t root_path_cost() const
        void root_path_cost(uint32_t new_root_path_cost)

        uint16_t port_id() const
        void port_id(uint16_t new_port_id)

        uint16_t msg_age() const
        void msg_age(uint16_t new_msg_age)

        uint16_t max_age() const
        void max_age(uint16_t new_max_age)

        uint16_t hello_time() const
        void hello_time(uint16_t new_hello_time)

        uint16_t fwd_delay() const
        void fwd_delay(uint16_t new_fwd_delay)

        bpdu_id_type root_id() const
        void root_id(const bpdu_id_type &ident)

        bpdu_id_type bridge_id() const
        void bridge_id(const bpdu_id_type &ident)


cdef class bpdu_id(object):
    cdef small_uint4 _priority
    cdef small_uint12 _ext_id
    cdef cppHWAddress6 _id

    cdef bpdu_id_type to_native(self)

    @staticmethod
    cdef from_native(bpdu_id_type t)


cdef class STP(PDU):
    cdef cppSTP* ptr

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return STP()
        obj = STP(_raw=True)
        obj.ptr = new cppSTP(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppSTP*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj
