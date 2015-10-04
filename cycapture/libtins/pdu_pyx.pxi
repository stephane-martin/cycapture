# -*- coding: utf-8 -*-
"""
Abstract PDU python class
"""

cdef class PDU(object):
    """
    Generic Protocol Data Unit
    """
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

    pdu_type = -1
    datalink_type = -1

    property header_size:
        def __get__(self):
            return int(self.base_ptr.header_size())

    property trailer_size:
        def __get__(self):
            return int(self.base_ptr.trailer_size())

    property size:
        def __get__(self):
            return int(self.base_ptr.size())

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

    cpdef int get_pdu_type(self):
        return <int> self.pdu_type

    cpdef copy(self):
        cdef string classname = map_pdutype_to_classname[self.get_pdu_type()]
        return (map_classname_to_factory[classname])(self.base_ptr.clone(), NULL, 0, None)

    cpdef reference(self):
        cdef string classname = map_pdutype_to_classname[self.get_pdu_type()]
        return (map_classname_to_factory[classname])(self.base_ptr, NULL, 0, self)

    cpdef copy_inner_pdu(self):
        cdef cppPDU* inner = self.base_ptr.inner_pdu()
        if inner == NULL:
            return None
        cdef string classname = map_pdutype_to_classname[<PDUType> inner.pdu_type()]
        return (map_classname_to_factory[classname])(inner.clone(), NULL, 0, None)

    cpdef ref_inner_pdu(self):
        cdef cppPDU* inner = self.base_ptr.inner_pdu()
        if inner == NULL:
            return None
        cdef string classname = map_pdutype_to_classname[<PDUType> inner.pdu_type()]
        return (map_classname_to_factory[classname])(inner, NULL, 0, self)

    cpdef set_inner_pdu(self, obj):
        if obj is None:
            raise ValueError("obj can't be None")
        elif not isinstance(obj, PDU):
            raise ValueError("obj is not a PDU")
        else:
            # (C++ set inner_pdu method destroys the previous inner PDU if it existed)
            # we clone the other obj, so that libtins can destroy it later safely when inner_pdu is called again
            self.base_ptr.inner_pdu(<cppPDU*>(<PDU>obj).base_ptr.clone())

    def __div__(self, other):
        if not isinstance(other, PDU):
            raise ValueError("other must be a PDU object")
        copy_of_self = <PDU> (self.copy())
        cdef cppPDU *last = copy_of_self.base_ptr
        while last.inner_pdu() != NULL:
            last = last.inner_pdu()
        last.inner_pdu(<const cppPDU &>((<PDU>other).base_ptr[0]))      # clone other
        return copy_of_self

    def __truediv__(self, other):
        return self.__div__(other)

    def __idiv__(self, other):
        if not isinstance(other, PDU):
            raise ValueError("other must be a PDU object")
        if not isinstance(other, PDU):
            raise ValueError("other must be a PDU object")
        cdef cppPDU *last = self.base_ptr
        while last.inner_pdu() != NULL:
            last = last.inner_pdu()
        last.inner_pdu(<const cppPDU &>((<PDU>other).base_ptr[0]))      # clone other
        return self

    def __itruediv__(self, other):
        return self.__idiv__(other)

    cpdef find_pdu_by_type(self, int t):
        cdef string classname = map_pdutype_to_classname[t]
        if classname.size() == 0:
            raise ValueError("Unknown PDU type")
        cdef cppPDU* pdu = cpp_find_pdu(<const cppPDU*> self.base_ptr, <PDUType> t)
        if pdu is NULL:
            raise PDUNotFound
        # here we return a *copy* of the matching inner PDu
        return (map_classname_to_factory[classname])(pdu.clone(), NULL, 0, None)

    cpdef rfind_pdu_by_type(self, int t):
        cdef string classname = map_pdutype_to_classname[t]
        if classname.size() == 0:
            raise ValueError("Unknown PDU type")
        cdef cppPDU* pdu = cpp_find_pdu(<const cppPDU*> self.base_ptr, <PDUType> t)
        if pdu is NULL:
            raise PDUNotFound
        # here we return a *reference* of the matching inner PDU
        return (map_classname_to_factory[classname])(pdu, NULL, 0, self)

    cpdef rfind_pdu_by_datalink_type(self, int t):
        if t == -1:
            raise PDUNotFound
        current_pdu = self
        while current_pdu is not None:
            if current_pdu.datalink_type == t:
                break
            current_pdu = current_pdu.ref_inner_pdu()
        if current_pdu is None:
            raise PDUNotFound
        return current_pdu

    cpdef find_pdu(self, obj):
        if isinstance(obj, type):
            if not hasattr(obj, "pdu_type"):
                raise ValueError("Don't know what to to with: %s (no attribute pdu_type)" % obj.__name__)
            if obj.pdu_type >= 0:
                return self.find_pdu_by_type(<PDUType>obj.pdu_type)
            else:
                raise ValueError("Don't know what to to with: %s (pdu_type attr is negative)" % obj.__name__)
        elif isinstance(obj, bytes):
            obj = (<bytes> obj).lower()
            try:
                t = map_classname_to_pdutype.at(<string>obj)
            except IndexError:
                raise ValueError("There is no PDU called: %s" % obj)
            return self.find_pdu_by_type(t)
        else:
            return self.find_pdu_by_type(int(obj))

    cpdef rfind_pdu(self, obj):
        if isinstance(obj, type):
            if not hasattr(obj, "pdu_type"):
                raise ValueError("Don't know what to to with: %s (no attribute pdu_type)" % obj.__name__)
            if obj.pdu_type >= 0:
                return self.rfind_pdu_by_type(<PDUType> obj.pdu_type)
            else:
                raise ValueError("Don't know what to to with: %s (pdu_type attr is negative)" % obj.__name__)
        elif isinstance(obj, bytes):
            obj = (<bytes> obj).lower()
            try:
                t = map_classname_to_pdutype.at(<string>obj)
            except IndexError:
                raise ValueError("There is no PDU called: %s" % obj)
            return self.rfind_pdu_by_type(<PDUType> t)
        else:
            return self.rfind_pdu_by_type(int(obj))

    @staticmethod
    def from_typed_memoryview(int pdu_type, unsigned char[:] data):
        cdef string classname = map_pdutype_to_classname[pdu_type]
        if classname.size() == 0:
            raise ValueError("Unknown PDU type")
        return (map_classname_to_factory[classname])(NULL, <uint8_t*>((<cy_memoryview>data).get_item_pointer([])), len(data), None)

    @staticmethod
    def from_generic_buf(int pdu_type, object buf):
        return (map_pdutype_to_class[pdu_type])(buf=buf)

map_pdutype_to_class = {
    PDU.ETHERNET_II: EthernetII,
    PDU.IP: IP,
    PDU.TCP: TCP,
    PDU.RAW: RAW,
    PDU.UDP: UDP,
    PDU.DNS: DNS,
    PDU.ICMP: ICMP
}

#cdef cpp_map[int, string] map_pdutype_to_classname
map_pdutype_to_classname[PDU.ETHERNET_II] = "ethernetii"
map_pdutype_to_classname[PDU.IP] = "ip"
map_pdutype_to_classname[PDU.TCP] = "tcp"
map_pdutype_to_classname[PDU.RAW] = "raw"
map_pdutype_to_classname[PDU.UDP] = "udp"
map_pdutype_to_classname[PDU.DNS] = "dns"
map_pdutype_to_classname[PDU.ICMP] = "icmp"
map_pdutype_to_classname[PDU.ICMP] = "icmp"
map_pdutype_to_classname[PDU.ARP] = "arp"
map_pdutype_to_classname[PDU.RADIOTAP] = "radiotap"


#cdef cpp_map[string, factory] map_classname_to_factory
map_classname_to_factory["ethernetii"] = &EthernetII.factory
map_classname_to_factory["ip"] = &IP.factory
map_classname_to_factory["tcp"] = &TCP.factory
map_classname_to_factory["raw"] = &RAW.factory
map_classname_to_factory["udp"] = &UDP.factory
map_classname_to_factory["dns"] = &DNS.factory
map_classname_to_factory["icmp"] = &ICMP.factory
map_classname_to_factory["arp"] = &ARP.factory
map_classname_to_factory["radiotap"] = &RadioTap.factory

#cdef cpp_map[string, int] map_classname_to_pdutype
cdef pair[int, string] p
for p in map_pdutype_to_classname:
    map_classname_to_pdutype[p.second] = p.first


