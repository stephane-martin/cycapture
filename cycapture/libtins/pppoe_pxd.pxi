# -*- coding: utf-8 -*-

cdef extern from "tins/pppoe.h" namespace "Tins" nogil:
    enum PPPoE_TagTypes "Tins::PPPoE::TagTypes":
        PPPoE_END_OF_LIST "Tins::PPPoE::END_OF_LIST",
        PPPoE_SERVICE_NAME "Tins::PPPoE::SERVICE_NAME",
        PPPoE_AC_NAME "Tins::PPPoE::AC_NAME",
        PPPoE_HOST_UNIQ "Tins::PPPoE::HOST_UNIQ",
        PPPoE_AC_COOKIE "Tins::PPPoE::AC_COOKIE",
        PPPoE_VENDOR_SPECIFIC "Tins::PPPoE::VENDOR_SPECIFIC",
        PPPoE_RELAY_SESSION_ID "Tins::PPPoE::RELAY_SESSION_ID",
        PPPoE_SERVICE_NAME_ERROR "Tins::PPPoE::SERVICE_NAME_ERROR",
        PPPoE_AC_SYSTEM_ERROR "Tins::PPPoE::AC_SYSTEM_ERROR",
        PPPoE_GENERIC_ERROR "Tins::PPPoE::GENERIC_ERROR"


cdef extern from "wrap.h" namespace "Tins" nogil:
    cdef cppclass pppoe_tag:
        pppoe_tag()
        pppoe_tag(PPPoE_TagTypes opt)
        # pppoe_tag(PPPoE_TagTypes opt, size_t length)
        pppoe_tag(PPPoE_TagTypes opt, size_t length, const uint8_t *data)

        PPPoE_TagTypes option() const
        void option(PPPoE_TagTypes opt)
        const uint8_t* data_ptr() const
        size_t data_size() const
        size_t length_field() const

cdef extern from "tins/pppoe.h" namespace "Tins" nogil:
    PDUType pppoe_pdu_flag "Tins::PPPoE::pdu_flag"

    cppclass pppoe_vendor_spec_type "Tins::PPPoE::vendor_spec_type":
        uint32_t vendor_id
        vector[uint8_t] data
        pppoe_vendor_spec_type()
        pppoe_vendor_spec_type(uint32_t vendor_id)
        pppoe_vendor_spec_type(uint32_t vendor_id, const vector[uint8_t] &data)

    pppoe_vendor_spec_type pppoe_vendor_spec_type_from_option "Tins::PPPoE::vendor_spec_type::from_option" (const pppoe_tag &opt)

    cppclass cppPPPoE "Tins::PPPoE" (cppPDU):
        cppPPPoE()
        cppPPPoE(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        const cpp_list[pppoe_tag] &tags() const
        const pppoe_tag* search_tag(PPPoE_TagTypes identifier) const
        void add_tag(const pppoe_tag &option)

        small_uint4 version() const
        small_uint4 type() const
        uint8_t code() const
        uint16_t session_id() const
        uint16_t payload_length() const

        void version(small_uint4 new_version)
        void type(small_uint4 new_type)
        void code(uint8_t new_code)
        void session_id(uint16_t new_session_id)
        void payload_length(uint16_t new_payload_length)


        # tags getters and setters
        void end_of_list()

        void service_name(const string &value)
        void ac_name(const string &value)
        void host_uniq(const vector[uint8_t] &value)
        void ac_cookie(const vector[uint8_t] &value)
        void vendor_specific(const pppoe_vendor_spec_type &value)
        void relay_session_id(const vector[uint8_t] &value)
        void service_name_error(const string &value)
        void ac_system_error(const string &value)
        void generic_error(const string &value)

        string service_name() const
        string ac_name() const
        vector[uint8_t] host_uniq() const
        vector[uint8_t] ac_cookie() const
        pppoe_vendor_spec_type vendor_specific() const
        vector[uint8_t] relay_session_id() const
        string service_name_error() const
        string ac_system_error() const
        string generic_error() const


cdef class PPPoE(PDU):
    cdef cppPPPoE* ptr

    cpdef search_tag(self, tag_type)
    cpdef add_tag(self, tag_type, data=?)

    cpdef get_vendor_specific(self)
    cpdef set_vendor_specific(self, vendor_id, data)

