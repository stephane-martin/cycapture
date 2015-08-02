# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t
from libcpp.vector cimport vector
from libcpp.list cimport list as cpp_list
from libcpp.pair cimport pair

cdef extern from "tins/tcp.h" namespace "Tins":
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
    ctypedef enum TcpAltChecksums "Tins::TCP:AltChecksums":
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
        small_int4 data_offset() const
        void data_offset(small_int4 new_doff)
        void add_option(const tcp_pdu_option &opt)
        const cpp_list[tcp_pdu_option]& options() const
        small_int1 get_flag(TcpFlags tcp_flag) const
        void set_flag(TcpFlags tcp_flag, small_int1 value)
        small_int12 flags() const
        void flags(small_int12 value)
        uint16_t mss() const
        void mss(uint16_t value)
        uint8_t winscale() const
        void winscale(uint8_t value)
        void sack_permitted()
        bool has_sack_permitted() const
        void sack(const vector[uint32_t]& edges)
        const vector[uint32_t] sack() const
        void timestamp(uint32_t value, uint32_t reply)
        pair[uint32_t, uint32_t] timestamp() const
        TcpAltChecksums altchecksum() const
        void altchecksum(TcpAltChecksums value)


cdef extern from "wrap.h" namespace "Tins":
    cdef cppclass tcp_pdu_option:
        ip_pdu_option()
        ip_pdu_option(uint8_t opt, size_t length, const uint8_t *data)


cdef class TCP(PDU):
    cdef cppTCP* ptr

cdef factory_tcp(cppPDU* ptr, object parent)
cdef make_TCP_from_const_uchar_buf(const uint8_t* buf, int size)
cdef make_TCP_from_uchar_buf(uint8_t* buf, int size)
cpdef make_TCP_from_typed_memoryview(unsigned char[:] data)
