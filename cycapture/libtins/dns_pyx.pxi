cdef class DNS_Query(object):
    """
    Encapsulate a DNS query
    """
    def __cinit__(self, name=None, query_type=None, query_class=None):
        self.ptr = new cppDNS.cppQuery()
        if name is not None:
            self.ptr.dname(<string> bytes(name))
        if query_type is not None:
            query_type = int(query_type)
            self.ptr.set_type(<QueryType> query_type)
        if query_class is not None:
            query_class = int(query_class)
            self.ptr.query_class(<QueryClass> query_class)

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
            self.ptr = NULL

    def __init__(self, name=None, query_type=None, query_class=None):
        """
        __init__(name=None, query_type=None, query_class=None)

        Parameters
        ----------
        name: bytes
            domain name
        query_type: int
            query type
        query_class: int
            query class
        """

    property name:
        """
        Domain name (read-write property)
        """
        def __get__(self):
            return bytes(self.ptr.dname())
        def __set__(self, value):
            self.ptr.dname(<string> bytes(value))

    property query_type:
        """
        Query type (read-write property)
        """
        def __get__(self):
            return int(self.ptr.get_type())
        def __set__(self, value):
            value = int(value)
            #if value not in DNS.TYPES:
            #    raise ValueError("value is not a valid DNS query type")
            self.ptr.set_type(<QueryType> value)

    property query_class:
        """
        Query class (read-write property)
        """
        def __get__(self):
            return int(self.ptr.query_class())
        def __set__(self, value):
            value = int(value)
            #if value not in DNS.CLASSES:
            #    raise ValueError("value is not a valid DNS query class")
            self.ptr.query_class(<QueryClass> value)



cdef class DNS_Resource(object):
    """
    Encapsulate a DNS resource
    """
    def __cinit__(self, name=None, data=None, query_type=None, query_class=None, ttl=None):
        self.ptr = new cppDNS.cppResource()
        if name is not None:
            self.ptr.dname(<string> bytes(name))
        if data is not None:
            self.ptr.data(<string> bytes(data))
        if query_type is not None:
            query_type = int(query_type)
            #if query_type not in DNS.TYPES:
            #    raise ValueError("value is not a valid DNS query type")
            self.ptr.set_type(<QueryType> query_type)
        if query_class is not None:
            query_class = int(query_class)
            #if query_class not in DNS.CLASSES:
            #    raise ValueError("value is not a valid DNS query class")
            self.ptr.query_class(<QueryClass> query_class)
        if ttl is not None:
            self.ptr.ttl(<uint16_t> int(ttl))

    def __dealloc__(self):
        if self.ptr is not NULL:
            del self.ptr
            self.ptr = NULL

    def __init__(self, name=None, data=None, query_type=None, query_class=None, ttl=None):
        """
        __init__(name=None, data=None, query_type=None, query_class=None, ttl=None)

        Parameters
        ----------
        name: bytes
            The domain name for which this record provides an answer.
        data: bytes
            The resource's payload
        query_type: int
            record type
        query_class: int
            record class
        ttl: int
            record TTL

        Note
        ====
        The data will be encoded properly by the DNS class before being added to this packet. That means that if the
        type is A or AAAA, it will be properly encoded as an IPv4 or IPv6 address. The same happens for records that
        contain domain names, such as NS or CNAME. This data will be encoded using DNS domain name encoding.
        """

    property name:
        """
        Domain name (read-write property)
        """
        def __get__(self):
            return bytes(self.ptr.dname())
        def __set__(self, value):
            self.ptr.dname(<string> bytes(value))

    property data:
        """
        This resource's payload (read-write property)
        """
        def __get__(self):
            return bytes(self.ptr.data())
        def __set__(self, value):
            self.ptr.data(<string> bytes(value))

    property query_type:
        """
        Record type (read-write property)
        """
        def __get__(self):
            return int(self.ptr.get_type())
        def __set__(self, value):
            value = int(value)
            self.ptr.set_type(<QueryType> value)

    property query_class:
        """
        Record class (read-write property)
        """
        def __get__(self):
            return int(self.ptr.query_class())
        def __set__(self, value):
            value = int(value)
            #if value not in DNS.CLASSES:
            #    raise ValueError("value is not a valid DNS query class")
            self.ptr.query_class(<QueryClass> value)

    property ttl:
        """
        Record TTL (read-write property)
        """
        def __get__(self):
            return int(self.ptr.ttl())
        def __set__(self, value):
            self.ptr.ttl(<uint16_t> int(value))


# noinspection PyDocstring
cdef class DNS(PDU):
    """
    DNS Protocol Data Unit
    """
    pdu_flag = PDU.DNS
    pdu_type = PDU.DNS

    QUERY = DNS_QUERY
    RESPONSE = DNS_RESPONSE

    A = DNS_A
    NS = DNS_NS
    MD = DNS_MD
    MF = DNS_MF
    CNAME = DNS_CNAME
    SOA = DNS_SOA
    MB = DNS_MB
    MG = DNS_MG
    MR = DNS_MR
    NULL_R = DNS_NULL_R
    WKS = DNS_WKS
    PTR = DNS_PTR
    HINFO = DNS_HINFO
    MINFO = DNS_MINFO
    MX = DNS_MX
    TXT = DNS_TXT
    RP = DNS_RP
    AFSDB = DNS_AFSDB
    X25 = DNS_X25
    ISDN = DNS_ISDN
    RT = DNS_RT
    NSAP = DNS_NSAP
    NSAP_PTR = DNS_NSAP_PTR
    SIG = DNS_SIG
    KEY = DNS_KEY
    PX = DNS_PX
    GPOS = DNS_GPOS
    AAAA = DNS_AAAA
    LOC = DNS_LOC
    NXT = DNS_NXT
    EID = DNS_EID
    NIMLOC = DNS_NIMLOC
    SRV = DNS_SRV
    ATMA = DNS_ATMA
    NAPTR = DNS_NAPTR
    KX = DNS_KX
    CERT = DNS_CERT
    A6 = DNS_A6
    DNAM = DNS_DNAM
    SINK = DNS_SINK
    OPT = DNS_OPT
    APL = DNS_APL
    DS = DNS_DS
    SSHFP = DNS_SSHFP
    IPSECKEY = DNS_IPSECKEY
    RRSIG = DNS_RRSIG
    NSEC = DNS_NSEC
    DNSKEY = DNS_DNSKEY
    DHCID = DNS_DHCID
    NSEC3 = DNS_NSEC3
    NSEC3PARAM = DNS_NSEC3PARAM

    TYPES = (A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL_R, WKS, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, X25, ISDN, RT,
             NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA, LOC, NXT, EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAM, SINK,
             OPT, APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM)

    IN = DNS_IN
    CH = DNS_CH
    HS = DNS_HS
    ANY = DNS_ANY

    CLASSES = (IN, CH, HS, ANY)

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppDNS()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDNS(buf_addr, size)

    def __init__(self, buf=None, _raw=False):
        """
        __init__(buf=None, _raw=False)

        Parameters
        ----------
        buf: memoryview or bytes or bytearray, optional
            the buffer containing the PDU data
        _raw: bool, optional
            if True, don't initialize the PDU (end users should not use this)
        """

    property ident:
        """
        id field (read-write property)
        """
        def __get__(self):
            return int(self.ptr.ident())
        def __set__(self, value):
            self.ptr.ident(<uint16_t> int(value))

    property qrtype:
        """
        type field (read-write property).

        Can be ``DNS.Query`` or ``DNS.Response``.
        """
        def __get__(self):
            return int(self.ptr.get_type())
        def __set__(self, value):
            value = int(value)
            #if value not in (DNS.QUERY, DNS.RESPONSE):
            #    raise ValueError("invalid qrtype")
            self.ptr.set_type(<QRType> value)

    property opcode:
        """
        opcode field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.opcode())
        def __set__(self, value):
            self.ptr.opcode(<uint8_t>int(value))

    property authoritative_answer:
        """
        authoritative answer field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.authoritative_answer())
        def __set__(self, value):
            self.ptr.authoritative_answer(<uint8_t>int(value))

    property truncated:
        """
        truncated field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.truncated())
        def __set__(self, value):
            self.ptr.truncated(<uint8_t>int(value))

    property recursion_desired:
        """
        recursion desired field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.recursion_desired())
        def __set__(self, value):
            self.ptr.recursion_desired(<uint8_t>int(value))

    property recursion_available:
        """
        recursion available field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.recursion_available())
        def __set__(self, value):
            self.ptr.recursion_available(<uint8_t>int(value))

    property z:
        """
        z field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.z())
        def __set__(self, value):
            self.ptr.z(<uint8_t>int(value))

    property authenticated_data:
        """
        authenticated data field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.authenticated_data())
        def __set__(self, value):
            self.ptr.authenticated_data(<uint8_t>int(value))

    property checking_disabled:
        """
        checking disabled field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.checking_disabled())
        def __set__(self, value):
            self.ptr.checking_disabled(<uint8_t>int(value))

    property rcode:
        """
        rcode field (read-write property).
        """
        def __get__(self):
            return int(self.ptr.rcode())
        def __set__(self, value):
            self.ptr.rcode(<uint8_t>int(value))

    cpdef uint16_t queries_count(self):
        """
        queries_count()
        """
        return self.ptr.questions_count()

    cpdef uint16_t questions_count(self):
        """
        questions_count()
        """
        return self.ptr.questions_count()

    cpdef queries(self):
        """
        queries()
        Returns
        -------
        queries: list of :py:class:`~.DNS_Query`
            the list of DNS queries contained in the DNS PDU
        """
        results = []
        cdef cpp_list[cppDNS.cppQuery] l = self.ptr.queries()
        for q in l:
            results.append(DNS_Query(bytes(q.dname()), int(q.get_type()), int(q.query_class())))
        return results

    cpdef add_query(self, DNS_Query q):
        """
        add_query(DNS_Query q)
        Add a query to perform.

        Parameters
        ----------
        q: :py:class:`~.DNS_Query`
            the query to be added
        """
        if q is None:
            return
        self.ptr.add_query(q.ptr[0])

    cpdef uint16_t answers_count(self):
        """
        answers_count()
        """
        return self.ptr.answers_count()

    cpdef answers(self):
        """
        answers()
        Returns
        -------
        answers: list of :py:class:`~.DNS_Resource`
            the list of DNS answers contained in the DNS PDU
        """
        results = []
        cdef cpp_list[cppDNS.cppResource] l = self.ptr.answers()
        for answer in l:
            results.append(
                DNS_Resource(
                    bytes(answer.dname()), bytes(answer.data()), int(answer.get_type()), int(answer.query_class()), int(answer.ttl())
                )
            )
        return results

    cpdef add_answer(self, DNS_Resource answer):
        """
        add_answer(DNS_Resource answer)
        Add an answer resource record.

        Parameters
        ----------
        answer: :py:class:`~.DNS_Resource`
            the answer to be added
        """
        if answer is None:
            return
        self.ptr.add_answer(answer.ptr[0])

    cpdef uint16_t authority_count(self):
        """
        authority_count()
        """
        return self.ptr.authority_count()

    cpdef authority(self):
        """
        authority()
        Returns
        -------
        authority: list of :py:class:`~.DNS_Resource`
            the list of DNS authority records contained in the DNS PDU
        """
        results = []
        cdef cpp_list[cppDNS.cppResource] l = self.ptr.authority()
        for auth in l:
            results.append(
                DNS_Resource(
                    bytes(auth.dname()), bytes(auth.data()), int(auth.get_type()), int(auth.query_class()), int(auth.ttl())
                )
            )
        return results

    cpdef add_authority(self, DNS_Resource authority):
        """
        add_authority(DNS_Resource authority)
        Add an authority resource record.

        Parameters
        ----------
        authority: :py:class:`~.DNS_Resource`
            the authority record to be added
        """
        if authority is None:
            return
        self.ptr.add_authority(authority.ptr[0])

    cpdef uint16_t additional_count(self):
        return self.ptr.additional_count()

    cpdef additional(self):
        """
        additional()
        Returns
        -------
        additional: list of :py:class:`~.DNS_Resource`
            the list of DNS additional records contained in the DNS PDU
        """
        results = []
        cdef cpp_list[cppDNS.cppResource] l = self.ptr.additional()
        for add in l:
            results.append(
                DNS_Resource(
                    bytes(add.dname()), bytes(add.data()), int(add.get_type()), int(add.query_class()), int(add.ttl())
                )
            )
        return results

    cpdef add_additional(self, DNS_Resource additional):
        """
        add_additional(DNS_Resource additional)
        Add an additional resource record.

        Parameters
        ----------
        additional: :py:class:`~.DNS_Resource`
            the record to be added
        """
        if additional is None:
            return
        self.ptr.add_additional(additional.ptr[0])

cpdef encode_domain_name(domain_name):
    """
    encode_domain_name(domain_name)
    """
    if not PyBytes_Check(domain_name):
        domain_name = bytes(domain_name)
    return <bytes>(cpp_encode_domain_name(<string>domain_name))
