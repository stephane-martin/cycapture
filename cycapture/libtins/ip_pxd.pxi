# -*- coding: utf-8 -*-

cdef extern from "wrap.h" namespace "Tins" nogil:
    cdef cppclass small_uint1:
        small_uint1()
        small_uint1(uint8_t) except +ValueError
    cdef cppclass small_uint4:
        small_uint4()
        small_uint4(uint8_t) except +ValueError
    cdef cppclass small_uint12:
        small_uint12()
        small_uint12(uint16_t) except +ValueError
    cdef cppclass small_uint24:
        small_uint24()
        small_uint24(uint32_t) except +ValueError


cdef extern from "tins/ip.h" namespace "Tins" nogil:
    # noinspection PyUnresolvedReferences
    PDUType ip_pdu_flag "Tins::IP::pdu_flag"
    ctypedef enum OptionClass "Tins::IP::OptionClass":
        IP_OPT_CLASS_CONTROL "Tins::IP::CONTROL"
        IP_OPT_CLASS_MEASUREMENT "Tins::IP::MEASUREMENT"
    ctypedef enum OptionNumber "Tins::IP::OptionNumber":
        IP_OPT_NUMBER_END "Tins::IP::END",
        IP_OPT_NUMBER_NOOP "Tins::IP::NOOP",
        IP_OPT_NUMBER_SEC "Tins::IP::SEC",
        IP_OPT_NUMBER_LSSR "Tins::IP::LSSR",
        IP_OPT_NUMBER_TIMESTAMP "Tins::IP::TIMESTAMP",
        IP_OPT_NUMBER_EXTSEC "Tins::IP::EXTSEC",
        IP_OPT_NUMBER_RR "Tins::IP::RR",
        IP_OPT_NUMBER_SID "Tins::IP::SID",
        IP_OPT_NUMBER_SSRR "Tins::IP::SSRR",
        IP_OPT_NUMBER_MTUPROBE "Tins::IP::MTUPROBE",
        IP_OPT_NUMBER_MTUREPLY "Tins::IP::MTUREPLY",
        IP_OPT_NUMBER_EIP "Tins::IP::EIP",
        IP_OPT_NUMBER_TR "Tins::IP::TR",
        IP_OPT_NUMBER_ADDEXT "Tins::IP::ADDEXT",
        IP_OPT_NUMBER_RTRALT "Tins::IP::RTRALT",
        IP_OPT_NUMBER_SDB "Tins::IP::SDB",
        IP_OPT_NUMBER_DPS "Tins::IP::DPS",
        IP_OPT_NUMBER_UMP "Tins::IP::UMP",
        IP_OPT_NUMBER_QS "Tins::IP::QS"

    cdef cppclass cppIP "Tins::IP" (cppPDU):
        cppIP()
        cppIP(cppIPv4Address ip_dst) except +ValueError
        cppIP(cppIPv4Address ip_dst, cppIPv4Address ip_src) except +ValueError
        cppIP(const uint8_t* buf, uint32_t total_sz) except +ValueError
        small_uint4 head_len() const
        uint8_t tos() const
        void tos(uint8_t new_tos)
        uint16_t tot_len() const
        #void tot_len(uint16_t new_tot_len)         private
        uint16_t ident "id"() const
        void ident "id"(uint16_t new_id)
        uint16_t frag_off() const
        void frag_off(uint16_t new_frag_off)
        uint8_t ttl() const
        void ttl(uint8_t new_ttl)
        uint8_t protocol() const
        void protocol(uint8_t new_protocol)
        uint16_t checksum() const
        #void checksum(uint16_t new_check)          private
        cppIPv4Address src_addr() const
        void src_addr(cppIPv4Address ip)
        cppIPv4Address dst_addr() const
        void dst_addr(cppIPv4Address ip)
        small_uint4 version() const
        void version(small_uint4 ver)
        cpp_bool is_fragmented() const


        # options
        void eol()
        void noop()
        uint16_t stream_identifier() const
        void stream_identifier(uint16_t stream_id) except+


        cppclass option_identifier:
            uint8_t number
            uint8_t op_class
            uint8_t copied
            option_identifier()
            option_identifier(uint8_t value)
            option_identifier(OptionNumber number, OptionClass op_class, small_uint1 copied)
            cpp_bool operator==(const option_identifier &rhs) const

        cppclass security_type:
            uint16_t security, compartments
            uint16_t handling_restrictions
            small_uint24 transmission_control
            security_type()
            security_type(uint16_t sec, uint16_t comp, uint16_t hand_res, small_uint24 tcc)

        cppclass generic_route_option_type:
            uint8_t pointer
            vector[cppIPv4Address] routes
            generic_route_option_type()
            generic_route_option_type(uint8_t ptr, vector[cppIPv4Address] rts)

        const cpp_list[ip_pdu_option] & options() const
        const ip_pdu_option *search_option(cppIP.option_identifier ident) const
        void add_option(const ip_pdu_option &opt)

        # options
        cppIP.security_type security() except+
        void security(const cppIP.security_type &data)
        cppIP.generic_route_option_type lsrr() except+
        void lsrr(const cppIP.generic_route_option_type &data)
        cppIP.generic_route_option_type ssrr() except+
        void ssrr(const cppIP.generic_route_option_type &data)
        cppIP.generic_route_option_type record_route() except+
        void record_route(const cppIP.generic_route_option_type &data)


    # typedef std::list<option> options_type;

cdef extern from "wrap.h" namespace "Tins" nogil:
    cdef cppclass ip_pdu_option:
        ip_pdu_option()
        ip_pdu_option(cppIP.option_identifier opt, size_t length, const uint8_t *data)

cdef extern from "tins/ip.h" namespace "Tins" nogil:
    cppIP.security_type security_type_from_option "Tins::IP::security_type::from_option"(const ip_pdu_option &opt)
    cppIP.generic_route_option_type generic_route_option_type_from_option "Tins::IP::generic_route_option_type::from_option" (const ip_pdu_option &opt)

cdef class IP(PDU):
    cdef cppIP* ptr
    cpdef eol(self)
    cpdef noop(self)
    cpdef cpp_bool is_fragmented(self)
    cpdef get_record_route(self)
    cpdef record_route(self, pointer, routes)
    cpdef get_lsrr(self)
    cpdef lsrr(self, pointer, routes)
    cpdef get_ssrr(self)
    cpdef ssrr(self, pointer, routes)

cdef factory_ip(cppPDU* ptr, object parent)

cdef make_IP_from_const_uchar_buf(const uint8_t* buf, int size)
cdef make_IP_from_uchar_buf(uint8_t* buf, int size)
cpdef make_IP_from_typed_memoryview(unsigned char[:] data)
