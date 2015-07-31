from libcpp.vector cimport vector

# noinspection PyUnresolvedReferences
ctypedef cppPDU* pointer

cdef extern from "tins/pdu.h" namespace "Tins":
    ctypedef vector[unsigned char] byte_array
    ctypedef vector[unsigned char] serialization_type "Tins::PDU::serialization_type"

    ctypedef enum endian_type "Tins::PDU::endian_type":
        BE "Tins::PDU::BE",
        LE "Tins::PDU::LE"

    cdef endian_type PDU_endianness "Tins::PDU::endianness"

    cdef cppclass cppPDU "Tins::PDU":
        cppPDU()
        unsigned int header_size() const
        unsigned int trailer_size() const
        unsigned int size() const
        cppPDU *inner_pdu() const
        cppPDU *release_inner_pdu()
        void inner_pdu(cppPDU *next_pdu)
        void inner_pdu(const cppPDU &next_pdu)
        serialization_type serialize()
        cppPDU *clone() const
        bool matches_flag(PDUType flag) const
        PDUType pdu_type()
        # noinspection PyUnresolvedReferences
        pointer find_pdu[T](PDUType type)

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
