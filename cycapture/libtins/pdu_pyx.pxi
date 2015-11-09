# -*- coding: utf-8 -*-
"""
Abstract PDU python class
"""

cdef class PDU(object):
    """
    Abstract Protocol Data Unit

    To build a PDU from a buffer::

        >>> buf = [
        ...     170, 187, 204, 221, 238, 255, 138, 139, 140, 141, 142, 143, 208, 171,
        ...     00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
        ...     00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
        ...     00, 00, 00, 00, 00, 00, 00, 00, 00, 00
        ... ]
        >>> buf = "".join([chr(i) for i in buf])
        >>> pdu = EthernetII.from_buffer(buf)

    PDU objects supports equality::

        >>> pdu1 = EthernetII.from_buffer(buf1)
        >>> pdu2 = EthernetII.from_buffer(buf2)
        >>> if pdu1 == pdu2:
        ...     print("Equals")

    PDU objects can be copied::

        >>> import copy
        >>> pdu1 = EthernetII.from_buffer(buf1)
        >>> pdu2 = pdu.copy()
        >>> pdu3 = copy.copy(pdu1)

    PDU objects can be pickled::

        >>> import pickle
        >>> pdu = EthernetII.from_buffer(buf1)
        >>> d = pickle.dumps(pdu)

    PDU can be built by concatenation::

        >>> pdu = EthernetII() / IP()

    PDU is abstract::

        >>> from cycapture.libtins import PDU
        >>> pdu = PDU()
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
          File "cycapture/libtins/pdu_pyx.pxi", line 190, in cycapture.libtins._tins.PDU.__cinit__
            raise NotImplementedError
        NotImplementedError
    """

    RAW = PDU_RAW
    Raw = PDU_RAW
    Ethernet = PDU_ETHERNET_II
    ETHERNETII = PDU_ETHERNET_II
    ETHERNET_II = PDU_ETHERNET_II
    IEEE802_3 = PDU_IEEE802_3
    DOT3 = PDU_IEEE802_3
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
    IPV6 = PDU_IPv6
    ICMPv6 = PDU_ICMPv6
    ICMPV6 = PDU_ICMPv6
    SLL = PDU_SLL
    DHCPv6 = PDU_DHCPv6
    DHCPV6 = PDU_DHCPv6
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


    def __richcmp__(self, other, op):
        if op == 2:   # equals ==
            return (<PDU> self).equals(other)
        if op == 3:   # different !=
            return not (<PDU> self).equals(other)
        raise ValueError("this comparison is not implemented")

    cdef equals(self, other):
        """
        equals(other)

        Parameters
        ----------
        other: object
            any Python object

        Returns
        -------
        bool
            Returns True if this PDU equals another
        """
        # this should be overloaded in concrete PDU classes to provide a more efficient equality test than the
        # "serialize" thing below
        if not isinstance(other, PDU):
            return False
        if self.pdu_type != other.pdu_type:
            return False
        cdef cppPDU* inner = self.base_ptr.inner_pdu()
        cdef cppPDU* other_inner = (<PDU> other).base_ptr.inner_pdu()
        if (inner is NULL) != (other_inner is NULL):
            return False
        if inner is not NULL:
            if inner.pdu_type() != other_inner.pdu_type():
                return False
        return self.serialize() == (<PDU> other).serialize()

    property header_size:
        """
        Returns the PDU's header size (read-only property)
        """
        def __get__(self):
            return int(self.base_ptr.header_size())

    property trailer_size:
        """
        Returns the PDU's trailer size (read-only property)
        """
        def __get__(self):
            return int(self.base_ptr.trailer_size())

    property size:
        """
        Returns the PDU's size (read-only property)
        """
        def __get__(self):
            return int(self.base_ptr.size())

    cpdef serialize(self):
        """
        serialize()
        Serialize the PDU

        Returns
        -------
        bytes
            the PDU as bytes
        """
        cdef vector[uint8_t] v = self.base_ptr.serialize()
        cdef uint8_t* p = &v[0]
        return <bytes> (p[:v.size()])

    def __cinit__(self):
        if type(self) == PDU:
            raise NotImplementedError

    def __dealloc__(self):
        pass

    def __init__(self):
        raise NotImplementedError

    cpdef int get_pdu_type(self):
        """
        get_pdu_type()

        Returns
        -------
        int
            The PDU type
        """
        return <int> self.pdu_type

    cpdef copy(self):
        """
        copy()
        Copy (deep-copy) the PDU

        Returns
        -------
        PDU: :py:class:`~.PDU`
            the cloned PDU
        """
        return PDU.from_ptr(self.base_ptr.clone(), parent=None)

    def __copy__(self):
        return PDU.from_ptr(self.base_ptr.clone(), parent=None)

    def __reduce__(self):
        return pdu_from_buffer, (self.serialize(), self.pdu_type)

    cpdef reference(self):
        """
        reference()
        Returns a reference of the current PDU

        Returns
        -------
        PDU: :py:class:`~.PDU`
            the reference
        """
        return PDU.from_ptr(self.base_ptr, parent=self)

    cpdef copy_inner_pdu(self):
        """
        copy_inner_pdu()
        Returns a copy of the inner PDU, or ``None`` if self has no child

        Returns
        -------
        PDU: :py:class:`~.PDU`
            A copy of the inner PDU
        """
        cdef cppPDU* inner = self.base_ptr.inner_pdu()
        if inner == NULL:
            return None
        return PDU.from_ptr(inner.clone(), parent=None)

    cpdef ref_inner_pdu(self):
        """
        ref_inner_pdu()
        Returns a reference to the inner PDU, or ``None`` if self has no child

        Returns
        -------
        PDU: :py:class:`~.PDU`
            A reference of the inner PDU
        """
        cdef cppPDU* inner = self.base_ptr.inner_pdu()
        if inner == NULL:
            return None
        return PDU.from_ptr(inner, parent=self)

    cpdef set_inner_pdu(self, obj):
        """
        set_inner_pdu(obj)
        Replace the inner PDU with obj.

        Note
        ----
        ``obj`` is cloned before being set as the inner PDU.

        Parameters
        ----------
        obj: :py:class:`~.PDU`
            the replacement PDU
        """
        if obj is None:
            self.base_ptr.inner_pdu(NULL)
        elif not isinstance(obj, PDU):
            raise ValueError("obj is not a PDU")
        else:
            # (C++ set inner_pdu method destroys the previous inner PDU if it existed)
            # we clone the other obj, so that libtins can destroy it later safely when inner_pdu is called again
            self.base_ptr.inner_pdu(<cppPDU*>(<PDU>obj).base_ptr.clone())

    def __div__(self, other):
        if (not isinstance(self, PDU)) or (not isinstance(other, PDU)):
            raise TypeError
        copy_of_self = <PDU> (self.copy())
        cdef cppPDU *last = copy_of_self.base_ptr
        while last.inner_pdu() != NULL:
            last = last.inner_pdu()
        last.inner_pdu(<const cppPDU &>((<PDU>other).base_ptr[0]))      # clone other
        return copy_of_self

    def __truediv__(self, other):
        return self.__div__(other)

    def __idiv__(self, other):
        if (not isinstance(self, PDU)) or (not isinstance(other, PDU)):
            raise TypeError
        cdef cppPDU *last = self.base_ptr
        while last.inner_pdu() != NULL:
            last = last.inner_pdu()
        last.inner_pdu(<const cppPDU &>((<PDU>other).base_ptr[0]))      # clone other
        return self

    def __itruediv__(self, other):
        return self.__idiv__(other)

    cpdef find_pdu_by_type(self, int t):
        """
        find_pdu_by_type(int t)
        Search the successive inner PDUs, by PDU type

        Parameters
        ----------
        t: int
            the type of the PDU that you're looking for

        Returns
        -------
        PDU: :py:class:`~.PDU`
            a copy of the matching inner PDU

        Raises
        ------
        PDUNotFound: :py:class:`~.PDUNotFound`
             if no marching PDU is found
        """
        cdef string classname = map_pdutype_to_classname[t]
        if classname.size() == 0:
            raise ValueError("Unknown PDU type")
        cdef cppPDU* pdu = cpp_find_pdu(<const cppPDU*> self.base_ptr, <PDUType> t)
        if pdu is NULL:
            raise PDUNotFound
        # here we return a *copy* of the matching inner PDU
        return PDU.from_ptr(pdu.clone(), parent=None)

    cpdef rfind_pdu_by_type(self, int t):
        """
        rfind_pdu_by_type(int t)
        Search the successive inner PDUs, by PDU type

        Parameters
        ----------
        t: int
            the type of the PDU that you're looking for

        Returns
        -------
        PDU: :py:class:`~.PDU`
            a reference of the matching inner PDU

        Raises
        ------
        PDUNotFound: :py:class:`~.PDUNotFound`
             if no marching PDU is found
        """
        cdef string classname = map_pdutype_to_classname[t]
        if classname.size() == 0:
            raise ValueError("Unknown PDU type")
        cdef cppPDU* pdu = cpp_find_pdu(<const cppPDU*> self.base_ptr, <PDUType> t)
        if pdu is NULL:
            raise PDUNotFound
        # here we return a *reference* of the matching inner PDU
        return PDU.from_ptr(pdu, parent=self)

    cpdef rfind_pdu_by_datalink_type(self, int t):
        """
        rfind_pdu_by_datalink_type(int t)
        Search the successive inner PDUs, by datalink type

        Parameters
        ----------
        t: int
            the datalink type of the PDU that you're looking for

        Returns
        -------
        PDU: :py:class:`~.PDU`
            a reference of the matching inner PDU

        Raises
        ------
        PDUNotFound: :py:class:`~.PDUNotFound`
             if no marching PDU is found
        """
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
        """
        Search the successive inner PDUs

        Parameters
        ----------
        obj: PDU class

        Returns
        -------
        PDU: :py:class:`~.PDU`
            a copy of the matching inner PDU

        Raises
        ------
        PDUNotFound: :py:class:`~.PDUNotFound`
             if no marching PDU is found
        """
        if inspect.isclass(obj):
            if not hasattr(obj, "pdu_type"):
                raise ValueError("Don't know what to to with: %s (no attribute pdu_type)" % obj.__name__)
            if obj.pdu_type >= 0:
                return self.find_pdu_by_type(<PDUType> obj.pdu_type)
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
        """
        rfind_pdu(obj)
        Search the successive inner PDUs

        Parameters
        ----------
        obj: PDU class

        Returns
        -------
        PDU: :py:class:`~.PDU`
            a reference of the matching inner PDU

        Raises
        ------
        PDUNotFound: :py:class:`~.PDUNotFound`
             if no marching PDU is found
        """
        if inspect.isclass(obj):
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

    cpdef matches_response(self, buf):
        """
        matches_response(buf)
        Checks if the given buffer can be a valid response to the current PDU

        Parameters
        ----------
        buf: bytes or bytearray or memoryview or cython memoryview

        Returns
        -------
        bool
            ``True`` if `buf` is a response to the PDU
        """
        cdef uint8_t* buf_addr
        cdef uint32_t size
        prepare_buf_arg(buf, &buf_addr, &size)
        return bool(self.base_ptr.matches_response(buf_addr, size))

    @classmethod
    def from_buffer(cls, buf):
        """
        from_buffer(buf)
        Factory classmethod, to make a concrete PDU from a buffer

        Parameters
        ----------
        buf: bytes or bytearray or memoryview or cython memoryview

        Returns
        -------
        PDU: :py:class:`~.PDU`
            The new PDU

        Raises
        ------
        MalformedPacket: :py:class:`~.MalformedPacket`
            if the given buffer can not be interpreted as an instance of the concrete PDU

        Note
        ----
        Class method
        """
        return pdu_from_buffer(buf, cls)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        raise NotImplementedError

    cdef replace_ptr(self, cppPDU* ptr):
        if ptr is NULL:
            raise NotImplementedError("... and ptr is NULL")
        else:
            raise NotImplementedError("ptr is a pointer to PDU of type: {}".format(ptr.pdu_type()))

    @staticmethod
    cdef from_ptr(cppPDU* ptr, parent=None):
        if ptr is NULL:
            raise ValueError
        if parent is not None and not isinstance(parent, PDU):
            raise TypeError
        cls = map_pdutype_to_class[ptr.pdu_type()]
        obj = cls.__new__(cls, _raw=True)
        (<PDU> obj).replace_ptr(ptr)
        (<PDU> obj).parent = parent
        (<PDU> obj).base_ptr = ptr
        return obj

    @staticmethod
    cdef prepare_buf_arg(object buf, uint8_t** buf_addr, uint32_t* size):
        prepare_buf_arg(buf, buf_addr, size)


map_pdutype_to_class = {
    PDU.ETHERNET_II: EthernetII,
    PDU.IP: IP,
    PDU.TCP: TCP,
    PDU.RAW: RAW,
    PDU.UDP: UDP,
    PDU.DNS: DNS,
    PDU.ICMP: ICMP,
    PDU.ARP: ARP,
    PDU.RADIOTAP: RadioTap,
    PDU.DOT3: Dot3,
    PDU.BOOTP: BootP,
    PDU.DHCP: DHCP,
    PDU.DOT1Q: Dot1Q,
    PDU.LOOPBACK: Loopback,
    PDU.LLC: LLC,
    PDU.SNAP: SNAP,
    PDU.STP: STP,
    PDU.SLL: SLL,
    PDU.PPPOE: PPPoE,
    PDU.EAPOL: EAPOL,
    PDU.RC4EAPOL: RC4EAPOL,
    PDU.RSNEAPOL: RSNEAPOL,
    PDU.PKTAP: PKTAP,
    PDU.PPI: PPI,
    PDU.IPSEC_AH: IPSecAH,
    PDU.IPSEC_ESP: IPSecESP,
    PDU.DOT11: Dot11,
    PDU.DOT11_DATA: Dot11Data,
    PDU.DOT11_QOS_DATA: Dot11QoSData,
    PDU.DOT11_DIASSOC: Dot11Disassoc,
    PDU.DOT11_ASSOC_REQ: Dot11AssocRequest,
    PDU.DOT11_ASSOC_RESP: Dot11AssocResponse,
    PDU.DOT11_REASSOC_REQ: Dot11ReAssocRequest,
    PDU.DOT11_REASSOC_RESP: Dot11ReAssocResponse,
    PDU.DOT11_AUTH: Dot11Authentication,
    PDU.DOT11_DEAUTH: Dot11Deauthentication,
    PDU.DOT11_BEACON: Dot11Beacon,
    PDU.DOT11_PROBE_REQ: Dot11ProbeRequest,
    PDU.DOT11_PROBE_RESP: Dot11ProbeResponse,
    PDU.DOT11_CONTROL: Dot11Control,
    PDU.DOT11_RTS: Dot11RTS,
    PDU.DOT11_PS_POLL: Dot11PSPoll,
    PDU.DOT11_CF_END: Dot11CFEnd,
    PDU.DOT11_END_CF_ACK: Dot11EndCFAck,
    PDU.DOT11_ACK: Dot11Ack,
    PDU.DOT11_BLOCK_ACK_REQ: Dot11BlockAckRequest,
    PDU.DOT11_BLOCK_ACK: Dot11BlockAck
}

# cdef cpp_map[int, string] map_pdutype_to_classname
map_pdutype_to_classname[PDU.ETHERNET_II] = "ethernetii"
map_pdutype_to_classname[PDU.IP] = "ip"
map_pdutype_to_classname[PDU.TCP] = "tcp"
map_pdutype_to_classname[PDU.RAW] = "raw"
map_pdutype_to_classname[PDU.UDP] = "udp"
map_pdutype_to_classname[PDU.DNS] = "dns"
map_pdutype_to_classname[PDU.ICMP] = "icmp"
map_pdutype_to_classname[PDU.ARP] = "arp"
map_pdutype_to_classname[PDU.RADIOTAP] = "radiotap"
map_pdutype_to_classname[PDU.DOT3] = "dot3"
map_pdutype_to_classname[PDU.BOOTP] = "bootp"
map_pdutype_to_classname[PDU.DHCP] = "dhcp"
map_pdutype_to_classname[PDU.DOT1Q] = "dot1q"
map_pdutype_to_classname[PDU.LOOPBACK] = "loopback"
map_pdutype_to_classname[PDU.LLC] = "llc"
map_pdutype_to_classname[PDU.SNAP] = "snap"
map_pdutype_to_classname[PDU.STP] = "stp"
map_pdutype_to_classname[PDU.SLL] = "sll"
map_pdutype_to_classname[PDU.PPPOE] = "pppoe"
map_pdutype_to_classname[PDU.EAPOL] = "eapol"
map_pdutype_to_classname[PDU.RC4EAPOL] = "rc4eapol"
map_pdutype_to_classname[PDU.RSNEAPOL] = "rsneapol"
map_pdutype_to_classname[PDU.PPI] = "ppi"
map_pdutype_to_classname[PDU.PKTAP] = "pktap"
map_pdutype_to_classname[PDU.IPSEC_ESP] = "ipsecesp"
map_pdutype_to_classname[PDU.IPSEC_AH] = "ipsecah"
map_pdutype_to_classname[PDU.DOT11] = "dot11"
map_pdutype_to_classname[PDU.DOT11_DATA] = "dot11data"
map_pdutype_to_classname[PDU.DOT11_QOS_DATA] = "dot11qosdata"
map_pdutype_to_classname[PDU.DOT11_DIASSOC] = "dot11disassoc"
map_pdutype_to_classname[PDU.DOT11_ASSOC_REQ] = "dot11assocreq"
map_pdutype_to_classname[PDU.DOT11_ASSOC_RESP] = " dot11assocresp"
map_pdutype_to_classname[PDU.DOT11_REASSOC_REQ] = "dot11reassocreq"
map_pdutype_to_classname[PDU.DOT11_REASSOC_RESP] = "dot11reassocresp"
map_pdutype_to_classname[PDU.DOT11_AUTH] = "dot11auth"
map_pdutype_to_classname[PDU.DOT11_DEAUTH] = "dot11deauth"
map_pdutype_to_classname[PDU.DOT11_BEACON] = " dot11beacon"
map_pdutype_to_classname[PDU.DOT11_PROBE_REQ] = "dot11probereq"
map_pdutype_to_classname[PDU.DOT11_PROBE_RESP] = "dot11proberesp"
map_pdutype_to_classname[PDU.DOT11_CONTROL] = "dot11control"
map_pdutype_to_classname[PDU.DOT11_RTS] = "dot11rts"
map_pdutype_to_classname[PDU.DOT11_PS_POLL] = "dot11pspoll"
map_pdutype_to_classname[PDU.DOT11_CF_END] = "dot11cfend"
map_pdutype_to_classname[PDU.DOT11_END_CF_ACK] = "dot11endcfack"
map_pdutype_to_classname[PDU.DOT11_ACK] = "dot11ack"
map_pdutype_to_classname[PDU.DOT11_BLOCK_ACK_REQ] = "dot11blockackreq"
map_pdutype_to_classname[PDU.DOT11_BLOCK_ACK] = "dot11clockack"

# cdef cpp_map[string, int] map_classname_to_pdutype
cdef pair[int, string] p
for p in map_pdutype_to_classname:
    map_classname_to_pdutype[p.second] = p.first


cpdef pdu_from_buffer(buf, cls):
    if not inspect.isclass(cls):
        cls = map_pdutype_to_class[int(cls)]
    if cls == PDU or not issubclass(cls, PDU):
        raise TypeError("cls must be a concrete PDU class")
    if buf is None:
        return cls()
    cdef uint8_t* buf_addr
    cdef uint32_t size
    obj = cls.__new__(cls, _raw=True)
    prepare_buf_arg(buf, &buf_addr, &size)
    cdef cppPDU* ptr = (<PDU> obj).replace_ptr_with_buf(buf_addr, size)
    (<PDU> obj).base_ptr = ptr
    (<PDU> obj).parent = None
    return obj


cdef prepare_buf_arg(object buf, uint8_t** buf_addr, uint32_t* size):
    if isinstance(buf, bytes) or isinstance(buf, bytearray):
        buf = memoryview(buf)
        buf_addr[0] = <uint8_t*> (mview_get_addr(<void*> buf))
        size[0] = <uint32_t> len(buf)
    elif isinstance(buf, memoryview):
        if buf.itemsize == 1 and buf.ndim == 1:
            buf_addr[0] = <uint8_t*> (mview_get_addr(<void*> buf))
            size[0] = <uint32_t> len(buf)
        else:
            raise MemoryViewFormat("the memoryview doesn't have the proper format")
    elif isinstance(buf, cy_memoryview):
        if buf.itemsize == 1 and buf.ndim == 1:
            buf_addr[0] = <uint8_t*> (<cy_memoryview>buf).get_item_pointer([])
            size[0] = <uint32_t> len(buf)
        else:
            raise MemoryViewFormat("the typed memoryview doesn't have the proper format")
    else:
        raise ValueError("don't know what to do with type '%s'" % type(buf))

