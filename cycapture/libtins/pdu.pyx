# -*- coding: utf-8 -*-
"""
Abstract PDU python class
"""
# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t

cdef class PDU(object):
    RAW = PDU_RAW
    ETHERNETII = PDU_ETHERNET_II
    ETHERNET_II = PDU_ETHERNET_II
    IEEE802_3 = PDU_IEEE802_3
    RADIOTAP = PDU_RADIOTAP
    DOT11 = PDU_DOT11
    DOT11_ACK = PDU_DOT11_ACK
    DOT11_ASSOC_REQ = PDU_DOT11_ASSOC_REQ
    DOT11_ASSOC_RESP = PDU_DOT11_ASSOC_RESP
    DOT11_AUTH = PDU_DOT11_AUTH
    DOT11_BEACON = PDU_DOT11_BEACON
    DOT11_BLOCK_ACK = PDU_DOT11_BLOCK_ACK
    DOT11_BLOCK_ACK_REQ = PDU_DOT11_BLOCK_ACK_REQ
    DOT11_CF_END = PDU_DOT11_CF_END
    DOT11_DATA = PDU_DOT11_DATA
    DOT11_CONTROL = PDU_DOT11_CONTROL
    DOT11_DEAUTH = PDU_DOT11_DEAUTH
    DOT11_DIASSOC = PDU_DOT11_DIASSOC
    DOT11_END_CF_ACK = PDU_DOT11_END_CF_ACK
    DOT11_MANAGEMENT = PDU_DOT11_MANAGEMENT
    DOT11_PROBE_REQ = PDU_DOT11_PROBE_REQ
    DOT11_PROBE_RESP = PDU_DOT11_PROBE_RESP
    DOT11_PS_POLL = PDU_DOT11_PS_POLL
    DOT11_REASSOC_REQ = PDU_DOT11_REASSOC_REQ
    DOT11_REASSOC_RESP = PDU_DOT11_REASSOC_RESP
    DOT11_RTS = PDU_DOT11_RTS
    DOT11_QOS_DATA = PDU_DOT11_QOS_DATA
    LLC = PDU_LLC
    SNAP = PDU_SNAP
    IP = PDU_IP
    ARP = PDU_ARP
    TCP = PDU_TCP
    UDP = PDU_UDP
    ICMP = PDU_ICMP
    BOOTP = PDU_BOOTP
    DHCP = PDU_DHCP
    EAPOL = PDU_EAPOL
    RC4EAPOL = PDU_RC4EAPOL
    RSNEAPOL = PDU_RSNEAPOL
    DNS = PDU_DNS
    LOOPBACK = PDU_LOOPBACK
    IPv6 = PDU_IPv6
    ICMPv6 = PDU_ICMPv6
    SLL = PDU_SLL
    DHCPv6 = PDU_DHCPv6
    DOT1Q = PDU_DOT1Q
    PPPOE = PDU_PPPOE
    STP = PDU_STP
    PPI = PDU_PPI
    IPSEC_AH = PDU_IPSEC_AH
    IPSEC_ESP = PDU_IPSEC_ESP
    PKTAP = PDU_PKTAP
    USER_DEFINED_PDU = PDU_USER_DEFINED_PDU

    property header_size:
        def __get__(self):
            return int(self.base_ptr.header_size())

    property trailer_size:
        def __get__(self):
            return int(self.base_ptr.trailer_size())

    cpdef serialize(self):
        cdef vector[uint8_t] v = self.base_ptr.serialize()
        cdef uint8_t* p = &v[0]
        return <bytes> (p[:v.size()])

    def __cinit__(self):
        pass

    def __dealloc__(self):
        pass

    def __init__(self):
        pass

    cpdef find_pdu_by_type(self, int t):
        if t not in _pdutypes:
            raise ValueError("Unknown PDU type")
        cdef cppPDU* pdu = cpp_find_pdu(<const cppPDU*> self.base_ptr, <PDUType> t)
        if pdu == NULL:
            raise NotFound
        # we create another python object. so that this new object is independant from self, and to prevent
        # memory freed twice in dealloc, we have to clone... so long for efficiency :(
        pdu = pdu.clone()
        klass = _mapping_pdutype_to_class[t]
        obj = klass(_no_init=True)
        obj.__set_ptr(<uintptr_t>pdu)
        return obj

    cpdef find_pdu_by_classname(self, bytes classname):
        if classname is None:
            raise ValueError("classname can't be None")
        classname = classname.lower()
        t = _mapping_classname_to_pdutype.get(classname)
        if t is None:
            raise ValueError("classname '%s' is unknown" % classname)
        return self.find_pdu_by_type(t)

    cpdef find_pdu_by_class(self, obj):
        if obj not in _classes:
            raise ValueError('unknown class')
        return self.find_pdu_by_type(obj.pdu_type)

    cpdef __set_ptr(self, uintptr_t ptr):
        self.base_ptr = <cppPDU*> ptr

cdef object _mapping_pdutype_to_class = {
    PDU_ETHERNET_II: EthernetII,
    PDU_IP: IP
}

cdef object _pdutypes = _mapping_pdutype_to_class.keys()
cdef object _classes = _mapping_pdutype_to_class.values()

_mapping_classname_to_pdutype = {
    "ethernet": PDU_ETHERNET_II,
    "ethernet2": PDU_ETHERNET_II,
    "ethernetii": PDU_ETHERNET_II,
    "ethernet_2": PDU_ETHERNET_II,
    "ethernet_ii": PDU_ETHERNET_II,
    "ip": PDU_IP,
    "ipv4": PDU_IP
}

class NotFound(Exception):
    pass
