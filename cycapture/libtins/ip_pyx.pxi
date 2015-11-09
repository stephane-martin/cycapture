# -*- coding: utf-8 -*-
"""
IP packet python class
"""

cdef class IPSecurityType(object):
    """
    The type for the IP security option.
    """
    # cdef uint16_t _security
    # cdef uint16_t _compartments
    # cdef uint16_t _handling_restrictions
    # cdef small_uint24 _transmission_control

    def __cinit__(self, security=0, compartments=0, handling_restrictions=0, transmission_control=0):
        self._security = <uint16_t> int(security)
        self._compartments = <uint16_t> int(compartments)
        self._handling_restrictions = <uint16_t> int(handling_restrictions)
        self._transmission_control = small_uint24(<uint32_t> int(transmission_control))

    def __init__(self, security=0, compartments=0, handling_restrictions=0, transmission_control=0):
        """
        __init__(security=0, compartments=0, handling_restrictions=0, transmission_control=0)

        Parameters
        ----------
        security: uint16_t
        compartments: uint16_t
        handling_restrictions: uint16_t
        transmission_control: 24 bits integer
        """

    def __repr__(self):
        return b"IP.SecurityType({}, {}, {}, {})".format(self.security, self.compartments, self.handling_restrictions, self.transmission_control)

    def __str__(self):
        return b"({}, {}, {}, {})".format(self.security, self.compartments, self.handling_restrictions, self.transmission_control)

    cdef cppIP.security_type to_cpp(self):
        return cppIP.security_type(self._security, self._compartments, self._handling_restrictions, self._transmission_control)

    @staticmethod
    cdef from_cpp(cppIP.security_type native):
        return IPSecurityType(native.security, native.compartments, native.handling_restrictions, <uint32_t> native.transmission_control)

    property security:
        """
        `security` getter
        """
        def __get__(self):
            return int(self._security)

    property compartments:
        """
        `compartments` getter
        """
        def __get__(self):
            return int(self._compartments)

    property handling_restrictions:
        """
        `handling_restrictions` getter
        """
        def __get__(self):
            return int(self._handling_restrictions)

    property transmission_control:
        """
        `transmission_control` getter
        """
        def __get__(self):
            return int(<uint32_t> self._transmission_control)

    def __richcmp__(self, other, op):
        if op == 2:
            return (<IPSecurityType> self).equals(other)
        if op == 3:
            return not (<IPSecurityType> self).equals(other)
        raise RuntimeError("unsupported operation: {}".format(op))

    cdef equals(self, other):
        if not isinstance(other, IPSecurityType):
            return False
        return (<IPSecurityType> self)._security == (<IPSecurityType> other)._security \
               and (<IPSecurityType> self)._compartments == (<IPSecurityType> other)._compartments \
               and (<IPSecurityType> self)._handling_restrictions == (<IPSecurityType> other)._handling_restrictions \
               and <uint32_t> ((<IPSecurityType> self)._transmission_control) == (<uint32_t> (<IPSecurityType> other)._transmission_control)

    def __hash__(self):
        return hash((self.security, self.compartments, self.handling_restrictions, self.transmission_control))


cdef class IPOptionIdentifier(object):
    """
    The type used to represent an IP option's identifier.
    """
    # cdef uint8_t _number
    # cdef uint8_t _op_class
    # cdef uint8_t _copied

    def __cinit__(self, number, op_class, copied):
        # (cppOptionNumber number, cppOptionclass op_class, small_uint1 copied)
        self._number = <uint8_t> (IP.OptionNumber(number))
        self._op_class = <uint8_t> (IP.OptionClass(op_class))
        self._copied = 1 if copied else 0

    def __init__(self, number, op_class, copied):
        """
        __init__(number, op_class, copied)

        Parameters
        ----------
        number: IP.OptionNumber or uint8_t
        op_class: IP.OptionClass or uint8_t
        copied: 1 or 0
        """

    def __repr__(self):
        return b"IP.OptionIdentifier({}, {}, {})".format(self.number, self.op_class, self.copied)

    def __str__(self):
        return b"({}, {}, {})".format(self.number, self.op_class, self.copied)

    cdef cppIP.option_identifier to_cpp(self):
        return cppIP.option_identifier(<cppOptionNumber> self._number, <cppOptionClass> self._op_class, small_uint1(self._copied))

    @staticmethod
    cdef from_cpp(cppIP.option_identifier native):
        return IPOptionIdentifier(native.number, native.op_class, native.copied)

    property number:
        """
        `number` getter
        """
        def __get__(self):
            return int(self._number)

    property op_class:
        """
        `op_class` getter
        """
        def __get__(self):
            return int(self._op_class)

    property copied:
        """
        `copied` getter
        """
        def __get__(self):
            return int(self._copied)

    def __richcmp__(self, other, op):
        if op == 2:
            return (<IPOptionIdentifier> self).equals(other)
        if op == 3:
            return not (<IPOptionIdentifier> self).equals(other)
        raise RuntimeError("unsupported operation: {}".format(op))

    cdef equals(self, other):
        if not isinstance(other, IPOptionIdentifier):
            return False
        return (<IPOptionIdentifier> self)._number == (<IPOptionIdentifier> other)._number \
               and (<IPOptionIdentifier> self)._op_class == (<IPOptionIdentifier> other)._op_class \
               and (<IPOptionIdentifier> self)._copied == (<IPOptionIdentifier> other)._copied

    def __hash__(self):
        return hash((self.number, self.op_class, self.copied))


cdef class IP(PDU):
    """
    IP packet
    """
    pdu_flag = PDU.IP
    pdu_type = PDU.IP

    SecurityType = IPSecurityType
    OptionIdentifier = IPOptionIdentifier

    OptionClass = make_enum('IP_OptionClass', 'OptionClass', "Options class for the IP PDU", {
        'CONTROL': IP_OPT_CLASS_CONTROL,
        'MEASUREMENT': IP_OPT_CLASS_MEASUREMENT
    })

    OptionNumber = make_enum('IP_OptionNumber', 'OptionNumber', "Options numbers for the IP PDU", {
        'END': IP_OPT_NUMBER_END,
        'NOOP': IP_OPT_NUMBER_NOOP,
        'SEC': IP_OPT_NUMBER_SEC,
        'LSSR': IP_OPT_NUMBER_LSSR,
        'TIMESTAMP': IP_OPT_NUMBER_TIMESTAMP,
        'EXTSEC': IP_OPT_NUMBER_EXTSEC,
        'RR': IP_OPT_NUMBER_RR,
        'SID': IP_OPT_NUMBER_SID,
        'SSRR': IP_OPT_NUMBER_SSRR,
        'MTUPROBE': IP_OPT_NUMBER_MTUPROBE,
        'MTUREPLY': IP_OPT_NUMBER_MTUREPLY,
        'EIP': IP_OPT_NUMBER_EIP,
        'TR': IP_OPT_NUMBER_TR,
        'ADDEXT': IP_OPT_NUMBER_ADDEXT,
        'RTRALT': IP_OPT_NUMBER_RTRALT,
        'SDB': IP_OPT_NUMBER_SDB,
        'DPS': IP_OPT_NUMBER_DPS,
        'UMP': IP_OPT_NUMBER_UMP,
        'QS': IP_OPT_NUMBER_QS
    })

    def __cinit__(self, dst_addr=None, src_addr=None, _raw=False):
        if _raw:
            return

        if not isinstance(src_addr, IPv4Address):
            src_addr = IPv4Address(src_addr)
        if not isinstance(dst_addr, IPv4Address):
            dst_addr = IPv4Address(dst_addr)

        self.ptr = new cppIP(<cppIPv4Address> ((<IPv4Address> dst_addr).ptr[0]), <cppIPv4Address> ((<IPv4Address> src_addr).ptr[0]))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dst_addr=None, src_addr=None):
        """
        __init__(dst_addr=None, src_addr=None)

        Parameters
        ----------
        dst_addr: bytes or :py:class:`~.IPv4Address`
            IPv4 destination address
        src_addr: bytes or :py:class:`~.IPv4Address`
            IPv4 source address
        """

    cpdef eol(self):
        """
        eol()
        Adds an End Of List option.
        """
        self.ptr.eol()

    cpdef noop(self):
        """
        noop()
        Adds a NOP option.
        """
        self.ptr.noop()

    property head_len:
        """
        the header length field (read-only)
        """
        def __get__(self):
            return <uint8_t> self.ptr.head_len()

    property tos:
        """
        the type of service field (``uint8_t``, read-write)
        """
        def __get__(self):
            return <uint8_t> self.ptr.tos()
        def __set__(self, value):
            cdef uint8_t v = <uint8_t> int(value)
            self.ptr.tos(v)

    property tot_len:
        """
        the total length field (``uint16_t``, read-write)
        """
        def __get__(self):
            return <uint16_t> self.ptr.tot_len()

    property id:
        """
        the id field (``uint16_t``, read-write)
        """
        def __get__(self):
            return <uint16_t> self.ptr.ident()
        def __set__(self, value):
            cdef uint16_t v = <uint16_t> int(value)
            self.ptr.ident(v)

    property frag_off:
        """
        the fragment offset field (``uint16_t``, read-write)
        """
        def __get__(self):
            return <uint16_t> self.ptr.frag_off()
        def __set__(self, value):
            cdef uint16_t v = <uint16_t> int(value)
            self.ptr.frag_off(v)

    property ttl:
        """
        the time to live field (``uint8_t``, read-write)
        """
        def __get__(self):
            return <uint8_t> self.ptr.ttl()
        def __set__(self, value):
            cdef uint8_t v = <uint8_t> int(value)
            self.ptr.ttl(v)

    property protocol:
        """
        the protocol field (``uint8_t``, read-write)
        """
        def __get__(self):
            return <uint8_t> self.ptr.protocol()
        def __set__(self, value):
            cdef uint8_t v = <uint8_t> int(value)
            self.ptr.protocol(v)

    property checksum:
        """
        the checksum field (``uint16_t``, read-write)
        """
        def __get__(self):
            return <uint16_t> self.ptr.checksum()

    property src_addr:
        """
        the source address field (``IPv4Address``, read-write)
        """
        def __get__(self):
            return IPv4Address(self.ptr.src_addr().to_uint32())
        def __set__(self, new_src):
            if isinstance(new_src, IPv4Address):
                self.ptr.src_addr((<IPv4Address> new_src).ptr[0])
            else:
                new_src = bytes(new_src)
                self.ptr.src_addr(cppIPv4Address(<string> new_src))

    property dst_addr:
        """
        the destination address field (``IPv4Address``, read-write)
        """
        def __get__(self):
            return IPv4Address(self.ptr.dst_addr().to_uint32())
        def __set__(self, new_dst):
            if isinstance(new_dst, IPv4Address):
                self.ptr.dst_addr((<IPv4Address> new_dst).ptr[0])
            else:
                new_dst = bytes(new_dst)
                self.ptr.dst_addr(cppIPv4Address(<string> new_dst))

    property version:
        """
        the version field (4 bits, read-write)
        """
        def __get__(self):
            return <uint8_t> self.ptr.version()
        def __set__(self, value):
            self.ptr.version(small_uint4(<uint8_t>int(value)))

    property fragmented:
        """
        ``True`` if the IP PDU is fragmented (read-only)
        """
        def __get__(self):
            return bool(self.ptr.is_fragmented())

    property stream_identifier:
        """
        Stream Identifier option (``uint16_t``, read-write)

        The getter returns ``None`` if the option is not set
        """
        def __get__(self):
            try:
                return <uint16_t> self.ptr.stream_identifier()
            except OptionNotFound:
                return None

        def __set__(self, value):
            self.ptr.stream_identifier(<uint16_t>int(value))

    cpdef set_record_route(self, pointer, routes):
        """
        set_record_route(pointer, routes)
        Adds a Record Route option.

        Parameters
        ----------
        pointer: uint8_t
        routes: list of IPv4 addresses
        """
        if isinstance(routes, IPv4Address) or isinstance(routes, bytes):
            routes = [routes]
        cdef vector[cppIPv4Address] v
        for addr in routes:
            v.push_back(IPv4Address(addr).ptr[0])
        cdef cppIP.generic_route_option_type r = cppIP.generic_route_option_type(<uint8_t>int(pointer), v)
        self.ptr.record_route(r)

    cpdef get_record_route(self):
        """
        get_record_route()
        Returns the record route option, or ``None`` is the option is not present.

        Returns
        -------
        pointer: int
        routes: list of IPv4Address
        """
        cdef cppIP.generic_route_option_type r
        try:
            r = self.ptr.record_route()
        except OptionNotFound:
            return None
        routes = [IPv4Address(route.to_uint32()) for route in r.routes]
        return int(r.pointer), routes

    cpdef set_lsrr(self, pointer, routes):
        """
        set_lsrr(pointer, routes)
        Adds a Loose Source and Record Route option.

        Parameters
        ----------
        pointer: uint8_t
        routes: list of IPv4 addresses
        """
        if isinstance(routes, IPv4Address) or isinstance(routes, bytes):
            routes = [routes]
        cdef vector[cppIPv4Address] v
        for addr in routes:
            v.push_back(IPv4Address(addr).ptr[0])
        cdef cppIP.generic_route_option_type r = cppIP.generic_route_option_type(<uint8_t>int(pointer), v)
        self.ptr.lsrr(r)

    cpdef get_lsrr(self):
        """
        get_lsrr()
        Searchs and returns a Loose Source and Record Route option, or ``None`` is the option is not present.

        Returns
        -------
        pointer: int
        routes: list of IPv4Address
        """
        cdef cppIP.generic_route_option_type r
        try:
            r = self.ptr.lsrr()
        except OptionNotFound:
            return None
        routes = [IPv4Address(route.to_uint32()) for route in r.routes]
        return int(r.pointer), routes

    cpdef set_ssrr(self, pointer, routes):
        """
        set_ssrr(pointer, routes)
        Adds a Strict Source and Record Route option.

        Parameters
        ----------
        pointer: uint8_t
        routes: list of IPv4 addresses
        """
        if isinstance(routes, IPv4Address) or isinstance(routes, bytes):
            routes = [routes]
        cdef vector[cppIPv4Address] v
        for addr in routes:
            v.push_back(IPv4Address(addr).ptr[0])
        cdef cppIP.generic_route_option_type r = cppIP.generic_route_option_type(<uint8_t>int(pointer), v)
        self.ptr.ssrr(r)

    cpdef get_ssrr(self):
        """
        get_ssrr()
        Searchs and returns a Strict Source and Record Route option, or ``None`` if the option is not present.

        Returns
        -------
        pointer: int
        routes: list of IPv4Address
        """
        cdef cppIP.generic_route_option_type r
        try:
            r = self.ptr.ssrr()
        except OptionNotFound:
            return None
        routes = [IPv4Address(route.to_uint32()) for route in r.routes]
        return int(r.pointer), routes

    cpdef get_security(self):
        """
        get_security()
        Searchs and returns a security option, or ``None`` if such option can't be found

        Returns
        -------
        opt: :py:class:`~.IPSecurityType`
        """
        cdef cppIP.security_type sec
        try:
            sec = self.ptr.security()
        except OptionNotFound:
            return None
        return IPSecurityType.from_cpp(sec)

    cpdef set_security(self, security_obj):
        """
        set_security(security_obj)
        Adds a security option.

        Parameters
        ----------
        security_obj: :py:class:`~.IPSecurityType`
            the security option
        """
        if not isinstance(security_obj, IPSecurityType):
            raise TypeError
        self.ptr.security((<IPSecurityType> security_obj).to_cpp())

    cpdef set_security_ex(self, security=0, compartments=0, handling_restrictions=0, transmission_control=0):
        self.ptr.security(IPSecurityType(security, compartments, handling_restrictions, transmission_control).to_cpp())

    cpdef add_option(self, identifier, data=None):
        """
        add_option(identifier, data=None)
        Adds an IP option.

        Parameters
        ----------
        identifier: :py:class:`~.IPOptionIdentifier`
            option identifier
        data: bytes
            option data
        """
        if not isinstance(identifier, IPOptionIdentifier):
            raise TypeError
        data = "" if data is None else bytes(data)
        length = len(data)
        cdef ip_pdu_option opt
        if length:
            opt = ip_pdu_option((<IPOptionIdentifier> identifier).to_cpp(), <size_t> (<int> length), <uint8_t*> (<bytes> data))
        else:
            opt = ip_pdu_option((<IPOptionIdentifier> identifier).to_cpp())
        self.ptr.add_option(opt)

    cpdef search_option(self, identifier):
        """
        search_option(identifier)
        Searchs for an option that matchs the given flag. Returns the option data, or ``None`` if such option can't be
        found.

        Parameters
        ----------
        identifier: :py:class:`~.IPOptionIdentifier`

        Returns
        -------
        opt: bytes
        """
        if not isinstance(identifier, IPOptionIdentifier):
            raise TypeError
        cdef ip_pdu_option* cpp_opt = <ip_pdu_option*> self.ptr.search_option((<IPOptionIdentifier> identifier).to_cpp())
        if cpp_opt is NULL:
            return None
        cdef int length = cpp_opt.data_size()
        if not length:
            return ""
        return <bytes> ((cpp_opt.data_ptr())[:length])

    cpdef options(self):
        """
        options()
        Returns all the PDU's options.

        Returns
        -------
        opts: list of dicts
        """
        results = []
        cdef cpp_list[ip_pdu_option] opts = self.ptr.options()
        cdef ip_pdu_option opt
        for opt in opts:
            opt_length = int(opt.length_field())
            data_size = int(opt.data_size())
            data = b''
            if data_size > 0:
                data = <bytes>(opt.data_ptr()[:data_size])
            results.append({
                'type': IPOptionIdentifier.from_cpp(opt.option()),
                'length': opt_length,
                'data_size': data_size,
                'data': data
            })
        return results


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppIP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppIP*> ptr

IPV4 = IP
IPv4 = IP
