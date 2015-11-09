# -*- coding: utf-8 -*-

cdef extern from "tins/ip.h" namespace "Tins" nogil:
    PDUType ip_pdu_flag "Tins::IP::pdu_flag"

    ctypedef enum cppOptionClass "Tins::IP::OptionClass":
        IP_OPT_CLASS_CONTROL "Tins::IP::CONTROL"
        IP_OPT_CLASS_MEASUREMENT "Tins::IP::MEASUREMENT"

    ctypedef enum cppOptionNumber "Tins::IP::OptionNumber":
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
        cppIP(cppIPv4Address ip_dst) except +custom_exception_handler
        cppIP(cppIPv4Address ip_dst, cppIPv4Address ip_src) except +custom_exception_handler
        cppIP(const uint8_t* buf, uint32_t total_sz) except +custom_exception_handler
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
        uint16_t stream_identifier() except +custom_exception_handler
        void stream_identifier(uint16_t stream_id) except +custom_exception_handler

        cppclass option_identifier:
            uint8_t number
            uint8_t op_class
            uint8_t copied
            option_identifier()
            option_identifier(uint8_t value)
            option_identifier(cppOptionNumber number, cppOptionClass op_class, small_uint1 copied)
            cpp_bool operator==(const option_identifier &rhs) const

        cppclass security_type:
            uint16_t security
            uint16_t compartments
            uint16_t handling_restrictions
            small_uint24 transmission_control
            security_type()
            security_type(uint16_t sec)
            security_type(uint16_t sec, uint16_t comp)
            security_type(uint16_t sec, uint16_t comp, uint16_t hand_res)
            security_type(uint16_t sec, uint16_t comp, uint16_t hand_res, small_uint24 tcc)

        cppclass generic_route_option_type:
            uint8_t pointer
            vector[cppIPv4Address] routes
            generic_route_option_type()
            generic_route_option_type(uint8_t ptr)
            generic_route_option_type(uint8_t ptr, vector[cppIPv4Address] rts)

        const cpp_list[ip_pdu_option]& options() const
        const ip_pdu_option* search_option(cppIP.option_identifier ident) except +custom_exception_handler
        void add_option(const ip_pdu_option &opt) except +custom_exception_handler

        # options
        cppIP.security_type security() except +custom_exception_handler
        void security(const cppIP.security_type &data) except +custom_exception_handler

        cppIP.generic_route_option_type lsrr() except +custom_exception_handler
        void lsrr(const cppIP.generic_route_option_type &data) except +custom_exception_handler

        cppIP.generic_route_option_type ssrr() except +custom_exception_handler
        void ssrr(const cppIP.generic_route_option_type &data) except +custom_exception_handler

        cppIP.generic_route_option_type record_route() except +custom_exception_handler
        void record_route(const cppIP.generic_route_option_type &data) except +custom_exception_handler


    # typedef std::list<option> options_type;

cdef extern from "wrap.h" namespace "Tins" nogil:
    cdef cppclass ip_pdu_option:
        ip_pdu_option()
        ip_pdu_option(cppIP.option_identifier opt)
        ip_pdu_option(cppIP.option_identifier opt, size_t length, const uint8_t* data)
        ip_pdu_option(const ip_pdu_option& rhs)
        # ip_pdu_option[ForwardIterator](cppIP.option_identifier opt, ForwardIterator start, ForwardIterator end)
        # ip_pdu_option[ForwardIterator](cppIP.option_identifier opt, size_t length, ForwardIterator start, ForwardIterator end)
        ip_pdu_option& operator=(const ip_pdu_option& rhs)
        cppIP.option_identifier option() const
        size_t data_size() const
        const uint8_t* data_ptr() const
        size_t length_field() const


cdef extern from "tins/ip.h" namespace "Tins" nogil:
    cppIP.security_type security_type_from_option "Tins::IP::security_type::from_option"(const ip_pdu_option &opt)
    cppIP.generic_route_option_type generic_route_option_type_from_option "Tins::IP::generic_route_option_type::from_option" (const ip_pdu_option &opt)

cdef class IP(PDU):
    cdef cppIP* ptr
    cpdef eol(self)
    cpdef noop(self)

    cpdef get_record_route(self)
    cpdef set_record_route(self, pointer, routes)

    cpdef get_lsrr(self)
    cpdef set_lsrr(self, pointer, routes)

    cpdef get_ssrr(self)
    cpdef set_ssrr(self, pointer, routes)

    cpdef get_security(self)
    cpdef set_security(self, security_obj)
    cpdef set_security_ex(self, security=?, compartments=?, handling_restrictions=?, transmission_control=?)
    cpdef add_option(self, identifier, data=?)
    cpdef search_option(self, identifier)
    cpdef options(self)

cdef class IPSecurityType(object):
    cdef uint16_t _security
    cdef uint16_t _compartments
    cdef uint16_t _handling_restrictions
    cdef small_uint24 _transmission_control

    cdef cppIP.security_type to_cpp(self)
    cdef equals(self, other)

    @staticmethod
    cdef from_cpp(cppIP.security_type native)

cdef class IPOptionIdentifier(object):
    cdef uint8_t _number
    cdef uint8_t _op_class
    cdef uint8_t _copied

    cdef cppIP.option_identifier to_cpp(self)
    cdef equals(self, other)

    @staticmethod
    cdef from_cpp(cppIP.option_identifier native)
