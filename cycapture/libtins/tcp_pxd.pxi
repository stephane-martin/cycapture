# -*- coding: utf-8 -*-

ctypedef vector[uint32_t] sack_type

cdef extern from "tins/tcp.h" namespace "Tins" nogil:
    PDUType tcp_pdu_flag "Tins::TCP::pdu_flag"
    ctypedef enum TcpFlags "Tins::TCP::Flags":
        TCP_FIN "Tins::TCP::FIN",
        TCP_SYN "Tins::TCP::SYN",
        TCP_RST "Tins::TCP::RST",
        TCP_PSH "Tins::TCP::PSH",
        TCP_ACK "Tins::TCP::ACK",
        TCP_URG "Tins::TCP::URG",
        TCP_ECE "Tins::TCP::ECE",
        TCP_CWR "Tins::TCP::CWR"
    ctypedef enum TcpOptionTypes "Tins::TCP::OptionTypes":
        TCP_EOL "Tins::TCP::EOL",
        TCP_NOP "Tins::TCP::NOP",
        TCP_MSS "Tins::TCP::MSS",
        TCP_WSCALE "Tins::TCP::WSCALE",
        TCP_SACK_OK "Tins::TCP::SACK_OK",
        TCP_SACK "Tins::TCP::SACK",
        TCP_TSOPT "Tins::TCP::TSOPT",
        TCP_ALTCHK "Tins::TCP::ALTCHK"
    ctypedef enum TcpAltChecksums "Tins::TCP::AltChecksums":
        TCP_CHK_TCP "Tins::TCP::CHK_TCP",
        TCP_CHK_8FLETCHER "Tins::TCP::CHK_8FLETCHER",
        TCP_CHK_16FLETCHER "Tins::TCP::CHK_16FLETCHER"

    # typedef std::list<option> options_type;
    # typedef std::vector<uint32_t> sack_type;

    cdef cppclass cppTCP "Tins::TCP" (cppPDU):
        cppTCP()
        cppTCP(uint16_t dport)
        cppTCP(uint16_t dport, uint16_t sport)
        cppTCP(const uint8_t *buf, uint32_t total_sz)
        uint16_t dport() const
        void dport(uint16_t new_dport)
        uint16_t sport() const
        void sport(uint16_t new_sport)
        uint32_t seq() const
        void seq(uint32_t new_seq)
        uint32_t ack_seq() const
        void ack_seq(uint32_t new_ack_seq)
        uint16_t window() const
        void window(uint16_t new_window)
        uint16_t checksum() const
        uint16_t urg_ptr() const
        void urg_ptr(uint16_t new_urg_ptr)
        small_uint4 data_offset() const
        void data_offset(small_uint4 new_doff)
        small_uint1 get_flag(TcpFlags tcp_flag) const
        void set_flag(TcpFlags tcp_flag, small_uint1 value)
        small_uint12 flags() const
        void flags(small_uint12 value)

        void add_option(const tcp_pdu_option &opt)
        const cpp_list[tcp_pdu_option]& options() const
        const tcp_pdu_option* search_option(TcpOptionTypes opt) const

        uint16_t mss() except+
        void mss(uint16_t value)
        uint8_t winscale() except+
        void winscale(uint8_t value)
        void sack_permitted()
        cpp_bool has_sack_permitted() const
        TcpAltChecksums altchecksum() except+
        void altchecksum(TcpAltChecksums value)
        void sack(const vector[uint32_t]& edges)
        const vector[uint32_t] sack() const
        void timestamp(uint32_t value, uint32_t reply)
        pair[uint32_t, uint32_t] timestamp() const


cdef extern from "wrap.h" namespace "Tins" nogil:
    cdef cppclass tcp_pdu_option:
        tcp_pdu_option()
        tcp_pdu_option(uint8_t opt, size_t length, const uint8_t *data)
        uint8_t option() const
        void option(uint8_t opt)
        const uint8_t *data_ptr() const
        size_t data_size() const
        size_t length_field() const
        #T to()[T] const


cdef class TCP(PDU):
    cdef cppTCP* ptr
    cpdef options(self)
    cpdef set_sack_permitted(self)
    cpdef get_flag(self, flag)
    cpdef set_flag(self, flag, cpp_bool value)

cdef factory_tcp(cppPDU* ptr, uint8_t* buf, int size, object parent)
