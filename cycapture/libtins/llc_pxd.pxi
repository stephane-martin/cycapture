# -*- coding: utf-8 -*-

cdef extern from "tins/llc.h" namespace "Tins" nogil:
    PDUType llc_pdu_flag "Tins::LLC::pdu_flag"

    cdef uint8_t LLC_GLOBAL_DSAP_ADDR "Tins::LLC::GLOBAL_DSAP_ADDR"
    cdef uint8_t LLC_NULL_ADDR "Tins::LLC::NULL_ADDR"

    enum LLC_Format "Tins::LLC::Format":
        LLC_INFORMATION "Tins::LLC::INFORMATION",
        LLC_SUPERVISORY "Tins::LLC::SUPERVISORY",
        LLC_UNNUMBERED "Tins::LLC::UNNUMBERED"

    enum LLC_ModifierFunctions "Tins::LLC::ModifierFunctions":
        LLC_UI "Tins::LLC::UI",
        LLC_XID "Tins::LLC::XID",
        LLC_TEST "Tins::LLC::TEST",
        LLC_SABME "Tins::LLC::SABME",
        LLC_DISC "Tins::LLC::DISC",
        LLC_UA "Tins::LLC::UA",
        LLC_DM "Tins::LLC::DM",
        LLC_FRMR "Tins::LLC::FRMR"

    enum LLC_SupervisoryFunctions "Tins::LLC::SupervisoryFunctions":
        LLC_RECEIVE_READY "Tins::LLC::RECEIVE_READY",
        LLC_REJECT "Tins::LLC::REJECT",
        LLC_RECEIVE_NOT_READY "Tins::LLC::RECEIVE_NOT_READY"

    cppclass cppLLC "Tins::LLC" (cppPDU):

        cppLLC()
        cppLLC(uint8_t dsap, uint8_t ssap)
        cppLLC(const uint8_t *buf, uint32_t total_sz)

        void group(cpp_bool value)
        void dsap(uint8_t new_dsap)
        void response(cpp_bool value)
        void ssap(uint8_t new_ssap)
        void type(LLC_Format t)
        void send_seq_number(uint8_t seq_number)
        void receive_seq_number(uint8_t seq_number)
        void poll_final(cpp_bool value)
        void supervisory_function(LLC_SupervisoryFunctions new_func)
        void modifier_function(LLC_ModifierFunctions mod_func)

        void add_xid_information(uint8_t xid_id, uint8_t llc_type_class, uint8_t receive_window)

        cpp_bool group()
        uint8_t dsap()
        cpp_bool response()
        uint8_t ssap()
        uint8_t type()
        uint8_t send_seq_number()
        uint8_t receive_seq_number()
        cpp_bool poll_final()
        uint8_t supervisory_function()
        uint8_t modifier_function()

        void clear_information_fields()
        # Delete all the information fields added.

cdef class LLC(PDU):
    cdef cppLLC* ptr

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return LLC()
        obj = LLC(_raw=True)
        obj.ptr = new cppLLC(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppLLC*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

    cpdef clear_information_fields(self)
