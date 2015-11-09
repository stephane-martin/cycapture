# -*- coding: utf-8 -*-

from ._py_exceptions import MemoryViewFormat

cdef extern from "tins/pdu.h" namespace "Tins" nogil:
    ctypedef vector[uint8_t] byte_array
    ctypedef vector[uint8_t] serialization_type "Tins::PDU::serialization_type"

    ctypedef enum endian_type "Tins::PDU::endian_type":
        BE "Tins::PDU::BE",
        LE "Tins::PDU::LE"

    cdef endian_type PDU_endianness "Tins::PDU::endianness"

    cdef cppclass cppPDU "Tins::PDU":
        cppPDU()
        uint32_t header_size() const
        uint32_t trailer_size() const
        uint32_t size() const
        cppPDU* inner_pdu() const
        cppPDU* release_inner_pdu()
        void inner_pdu(cppPDU *next_pdu) # takes ownership
        void inner_pdu(const cppPDU &next_pdu) # clone
        vector[uint8_t] serialize() except +custom_exception_handler
        cppPDU *clone() const
        cpp_bool matches_flag(PDUType flag) const
        PDUType pdu_type()
        # noinspection PyUnresolvedReferences
        (T*) find_pdu[T]()
        (const T*) find_pdu[T]() const
        (T&) rfind_pdu[T]()
        (const T&) rfind_pdu[T]() const
        cpp_bool matches_response(const uint8_t *ptr, uint32_t total_sz) except +custom_exception_handler
        cppPDU *recv_response(cppPacketSender &sender, const cppNetworkInterface &iface)

    T slash_op "Tins::PDU::operator/" [T] (T lop, const cppPDU& rop)
    (T&) slash_equals_op "Tins::PDU::operator/=" [T] (T& lop, const cppPDU& rop)
    (T*) pointer_slash_equals_op "Tins::PDU::operator/=" [T] (T* lop, const cppPDU &rop)

    ctypedef enum PDUType "Tins::PDU::PDUType":
        PDU_RAW "Tins::PDU::RAW",
        PDU_ETHERNET_II "Tins::PDU::ETHERNET_II",
        PDU_IEEE802_3 "Tins::PDU::IEEE802_3",
        PDU_RADIOTAP "Tins::PDU::RADIOTAP",
        PDU_DOT11 "Tins::PDU::DOT11",
        PDU_DOT11_ACK "Tins::PDU::DOT11_ACK",
        PDU_DOT11_ASSOC_REQ "Tins::PDU::DOT11_ASSOC_REQ",
        PDU_DOT11_ASSOC_RESP "Tins::PDU::DOT11_ASSOC_RESP",
        PDU_DOT11_AUTH "Tins::PDU::DOT11_AUTH",
        PDU_DOT11_BEACON "Tins::PDU::DOT11_BEACON",
        PDU_DOT11_BLOCK_ACK "Tins::PDU::DOT11_BLOCK_ACK",
        PDU_DOT11_BLOCK_ACK_REQ "Tins::PDU::DOT11_BLOCK_ACK_REQ",
        PDU_DOT11_CF_END "Tins::PDU::DOT11_CF_END",
        PDU_DOT11_DATA "Tins::PDU::DOT11_DATA",
        PDU_DOT11_CONTROL "Tins::PDU::DOT11_CONTROL",
        PDU_DOT11_DEAUTH "Tins::PDU::DOT11_DEAUTH",
        PDU_DOT11_DIASSOC "Tins::PDU::DOT11_DIASSOC",
        PDU_DOT11_END_CF_ACK "Tins::PDU::DOT11_END_CF_ACK",
        PDU_DOT11_MANAGEMENT "Tins::PDU::DOT11_MANAGEMENT",
        PDU_DOT11_PROBE_REQ "Tins::PDU::DOT11_PROBE_REQ",
        PDU_DOT11_PROBE_RESP "Tins::PDU::DOT11_PROBE_RESP",
        PDU_DOT11_PS_POLL "Tins::PDU::DOT11_PS_POLL",
        PDU_DOT11_REASSOC_REQ "Tins::PDU::DOT11_REASSOC_REQ",
        PDU_DOT11_REASSOC_RESP "Tins::PDU::DOT11_REASSOC_RESP",
        PDU_DOT11_RTS "Tins::PDU::DOT11_RTS",
        PDU_DOT11_QOS_DATA "Tins::PDU::DOT11_QOS_DATA",
        PDU_LLC "Tins::PDU::LLC",
        PDU_SNAP "Tins::PDU::SNAP",
        PDU_IP "Tins::PDU::IP",
        PDU_ARP "Tins::PDU::ARP",
        PDU_TCP "Tins::PDU::TCP",
        PDU_UDP "Tins::PDU::UDP",
        PDU_ICMP "Tins::PDU::ICMP",
        PDU_BOOTP "Tins::PDU::BOOTP",
        PDU_DHCP "Tins::PDU::DHCP",
        PDU_EAPOL "Tins::PDU::EAPOL",
        PDU_RC4EAPOL "Tins::PDU::RC4EAPOL",
        PDU_RSNEAPOL "Tins::PDU::RSNEAPOL",
        PDU_DNS "Tins::PDU::DNS",
        PDU_LOOPBACK "Tins::PDU::LOOPBACK",
        PDU_IPv6 "Tins::PDU::IPv6",
        PDU_ICMPv6 "Tins::PDU::ICMPv6",
        PDU_SLL "Tins::PDU::SLL",
        PDU_DHCPv6 "Tins::PDU::DHCPv6",
        PDU_DOT1Q "Tins::PDU::DOT1Q",
        PDU_PPPOE "Tins::PDU::PPPOE",
        PDU_STP "Tins::PDU::STP",
        PDU_PPI "Tins::PDU::PPI",
        PDU_IPSEC_AH "Tins::PDU::IPSEC_AH",
        PDU_IPSEC_ESP "Tins::PDU::IPSEC_ESP",
        PDU_PKTAP "Tins::PDU::PKTAP",
        PDU_USER_DEFINED_PDU "Tins::PDU::USER_DEFINED_PDU"


ctypedef object (*factory) (cppPDU * ptr, uint8_t* buf, int size, object parent)


cdef extern from "wrap.h" namespace "Tins" nogil:
    void slash_equals_op[T](T& lop, const cppPDU &rop)
    cppPDU* cpp_find_pdu(const cppPDU* pdu, PDUType t)


cdef public class PDU(object)[type PyPDUType, object PyPDUObject]:
    cdef cppPDU* base_ptr
    cdef object parent

    cpdef copy(self)
    cpdef reference(self)
    cpdef int get_pdu_type(self)
    cpdef find_pdu_by_type(self, int t)
    cpdef rfind_pdu_by_type(self, int t)
    cpdef rfind_pdu_by_datalink_type(self, int t)
    cpdef find_pdu(self, obj)
    cpdef rfind_pdu(self, obj)
    cpdef copy_inner_pdu(self)
    cpdef ref_inner_pdu(self)
    cpdef set_inner_pdu(self, obj)
    cpdef serialize(self)
    cpdef matches_response(self, buf)

    cdef equals(self, other)
    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL
    cdef replace_ptr(self, cppPDU* ptr)

    @staticmethod
    cdef prepare_buf_arg(object buf, uint8_t** buf_addr, uint32_t* size)

    @staticmethod
    cdef from_ptr(cppPDU* ptr, parent=?)

cdef cpp_map[int, string] map_pdutype_to_classname
cdef cpp_map[string, int] map_classname_to_pdutype
cdef dict map_pdutype_to_class
cpdef pdu_from_buffer(buf, cls)

