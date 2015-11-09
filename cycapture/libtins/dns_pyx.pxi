# -*- coding: utf-8 -*-

cdef class DNS_Query(object):
    """
    Encapsulate a DNS query
    """
    def __cinit__(self, name=None, query_type=None, query_class=None):
        self.cpp_query = cppDNS.cppQuery()
        if name is not None:
            self.cpp_query.dname(<string> bytes(name))
        if query_type is not None:
            query_type = int(query_type)
            self.cpp_query.set_type(<QueryType> query_type)
        if query_class is not None:
            query_class = int(query_class)
            self.cpp_query.query_class(<QueryClass> query_class)

    def __dealloc__(self):
        pass

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

    def __hash__(self):
        return hash((self.name, self.query_type, self.query_class))

    cdef equals(self, other):
        """
        equals(other)

        Parameters
        ----------
        other: object
            any python object

        Returns
        -------
        bool
            Returns True is self equals other
        """
        if not isinstance(other, DNS_Query):
            return False
        return self.name == (<DNS_Query> other).name \
               and self.query_type == (<DNS_Query> other).query_type \
               and self.query_class == (<DNS_Query> other).query_class

    def __richcmp__(self, other, op):
        if op == 2:   # equals ==
            return (<DNS_Query> self).equals(other)
        if op == 3:   # different !=
            return not (<DNS_Query> self).equals(other)
        raise ValueError("this comparison is not implemented")

    property name:
        """
        Domain name (read-only property)
        """
        def __get__(self):
            return bytes(self.cpp_query.dname())

    property query_type:
        """
        Query type (read-only property)
        """
        def __get__(self):
            return int(self.cpp_query.get_type())

    property query_class:
        """
        Query class (read-only property)
        """
        def __get__(self):
            return int(self.cpp_query.query_class())


cdef class DNS_Resource(object):
    """
    Encapsulate a DNS resource
    """
    def __cinit__(self, name=None, data=None, query_type=None, query_class=None, ttl=None):
        self.cpp_resource = cppDNS.cppResource()
        if name is not None:
            self.cpp_resource.dname(<string> bytes(name))
        if data is not None:
            self.cpp_resource.data(<string> bytes(data))
        if query_type is not None:
            query_type = int(query_type)
            self.cpp_resource.set_type(<QueryType> query_type)
        if query_class is not None:
            query_class = int(query_class)
            self.cpp_resource.query_class(<QueryClass> query_class)
        if ttl is not None:
            self.cpp_resource.ttl(<uint16_t> int(ttl))

    def __dealloc__(self):
        pass

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
            Returns True is self equals other
        """
        if not isinstance(other, DNS_Resource):
            return False

        return self.name == (<DNS_Resource> other).name \
               and self.data == (<DNS_Resource> other).data \
               and self.query_type == (<DNS_Resource> other).query_type \
               and self.query_class == (<DNS_Resource> other).query_class \
               and self.ttl == (<DNS_Resource> other).ttl

    def __hash__(self):
        return hash((self.name, self.data, self.query_type, self.query_class, self.ttl))

    def __richcmp__(self, other, op):
        if op == 2:   # equals ==
            return (<DNS_Resource> self).equals(other)
        if op == 3:   # different !=
            return not (<DNS_Resource> self).equals(other)

        raise ValueError("this comparison is not implemented")

    property name:
        """
        Domain name (read-only property)
        """
        def __get__(self):
            return bytes(self.cpp_resource.dname())

    property data:
        """
        This resource's payload (read-only property)
        """
        def __get__(self):
            return bytes(self.cpp_resource.data())

    property query_type:
        """
        Record type (read-only property)
        """
        def __get__(self):
            return int(self.cpp_resource.get_type())

    property query_class:
        """
        Record class (read-only property)
        """
        def __get__(self):
            return int(self.cpp_resource.query_class())

    property ttl:
        """
        Record TTL (read-only property)
        """
        def __get__(self):
            return int(self.cpp_resource.ttl())


cdef class DNS(PDU):
    """
    DNS Protocol Data Unit
    """
    pdu_flag = PDU.DNS
    pdu_type = PDU.DNS

    QRType = make_enum('DNS_QRType', 'QRType', 'Enum used to tell if the DNS PDU is DNS query or a DNS response', {
        'QUERY': DNS_QUERY,
        'RESPONSE': DNS_RESPONSE
    })

    QueryType = make_enum('DNS_QueryType', 'QueryType', 'Types of DNS queries', {
        'A': DNS_A,
        'NS': DNS_NS,
        'MD': DNS_MD,
        'MF': DNS_MF,
        'CNAME': DNS_CNAME,
        'SOA': DNS_SOA,
        'MB': DNS_MB,
        'MG': DNS_MG,
        'MR': DNS_MR,
        'NULL_R': DNS_NULL_R,
        'WKS': DNS_WKS,
        'PTR': DNS_PTR,
        'HINFO': DNS_HINFO,
        'MINFO': DNS_MINFO,
        'MX': DNS_MX,
        'TXT': DNS_TXT,
        'RP': DNS_RP,
        'AFSDB': DNS_AFSDB,
        'X25': DNS_X25,
        'ISDN': DNS_ISDN,
        'RT': DNS_RT,
        'NSAP': DNS_NSAP,
        'NSAP_PTR': DNS_NSAP_PTR,
        'SIG': DNS_SIG,
        'KEY': DNS_KEY,
        'PX': DNS_PX,
        'GPOS': DNS_GPOS,
        'AAAA': DNS_AAAA,
        'LOC': DNS_LOC,
        'NXT': DNS_NXT,
        'EID': DNS_EID,
        'NIMLOC': DNS_NIMLOC,
        'SRV': DNS_SRV,
        'ATMA': DNS_ATMA,
        'NAPTR': DNS_NAPTR,
        'KX': DNS_KX,
        'CERT': DNS_CERT,
        'A6': DNS_A6,
        'DNAM': DNS_DNAM,
        'SINK': DNS_SINK,
        'OPT': DNS_OPT,
        'APL': DNS_APL,
        'DS': DNS_DS,
        'SSHFP': DNS_SSHFP,
        'IPSECKEY': DNS_IPSECKEY,
        'RRSIG': DNS_RRSIG,
        'NSEC': DNS_NSEC,
        'DNSKEY': DNS_DNSKEY,
        'DHCID': DNS_DHCID,
        'NSEC3': DNS_NSEC3,
        'NSEC3PARAM': DNS_NSEC3PARAM
    })

    QueryClass = make_enum('DNS_QueryClass', 'QueryClass', 'Classes of DNS queries', {
        'IN': DNS_IN,
        'CH': DNS_CH,
        'HS': DNS_HS,
        'ANY': DNS_ANY
    })

    Query = DNS_Query
    Resource = DNS_Resource

    def __cinit__(self, _raw=False):
        if _raw:
            return

        self.ptr = new cppDNS()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self):
        """
        __init__()
        Constructor: ``DNS()``
        """

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    property id:
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

        Can be ``DNS.QRType.Query`` or ``DNS.QRType.Response``.
        """
        def __get__(self):
            return int(self.ptr.get_type())
        def __set__(self, value):
            value = int(value)
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

    cpdef queries_count(self):
        """
        queries_count()

        Returns
        -------
        int
            Returns the number of queries
        """
        return self.ptr.questions_count()

    cpdef questions_count(self):
        """
        questions_count()

        Returns
        -------
        int
            Returns the number of queries
        """
        return self.ptr.questions_count()

    cpdef get_queries(self):
        """
        get_queries()

        Returns
        -------
        queries: list of :py:class:`~.DNS_Query`
            the list of DNS queries contained in the DNS PDU
        """
        cdef cpp_list[cppDNS.cppQuery] queries = self.ptr.queries()
        return [DNS_Query(bytes(q.dname()), int(q.get_type()), int(q.query_class())) for q in queries]

    cpdef add_query(self, DNS_Query q):
        """
        add_query(q)
        Add a query to perform.

        Parameters
        ----------
        q: :py:class:`~.DNS_Query`
            the query to be added
        """
        if q is None:
            return
        self.ptr.add_query(q.cpp_query)

    cpdef answers_count(self):
        """
        answers_count()

        Returns
        -------
        int
            Returns the number of answers
        """
        return self.ptr.answers_count()

    cpdef get_answers(self):
        """
        get_answers()

        Returns
        -------
        answers: list of :py:class:`~.DNS_Resource`
            the list of DNS answers contained in the DNS PDU
        """
        cdef cpp_list[cppDNS.cppResource] answers = self.ptr.answers()
        return [
            DNS_Resource(bytes(a.dname()), bytes(a.data()), int(a.get_type()), int(a.query_class()), int(a.ttl()))
            for a in answers
        ]

    cpdef add_answer(self, DNS_Resource answer):
        """
        add_answer(answer)
        Add an answer resource record.

        Parameters
        ----------
        answer: :py:class:`~.DNS_Resource`
            the answer to be added
        """
        if answer is None:
            return
        self.ptr.add_answer(answer.cpp_resource)

    cpdef authority_count(self):
        """
        authority_count()

        Returns
        -------
        int
            Returns the number of authority records
        """
        return self.ptr.authority_count()

    cpdef get_authorities(self):
        """
        authority()

        Returns
        -------
        authority: list of :py:class:`~.DNS_Resource`
            the list of DNS authority records contained in the DNS PDU
        """
        cdef cpp_list[cppDNS.cppResource] auths = self.ptr.authority()
        return [
            DNS_Resource(bytes(auth.dname()), bytes(auth.data()), int(auth.get_type()), int(auth.query_class()), int(auth.ttl()))
            for auth in auths
        ]

    cpdef add_authority(self, DNS_Resource authority):
        """
        add_authority(authority)
        Add an authority resource record.

        Parameters
        ----------
        authority: :py:class:`~.DNS_Resource`
            the authority record to be added
        """
        if authority is None:
            return
        self.ptr.add_authority(authority.cpp_resource)

    cpdef additional_count(self):
        """
        additional_count()

        Returns
        -------
        int
            Returns the number of additional records
        """
        return self.ptr.additional_count()

    cpdef get_additionals(self):
        """
        get_additionals()

        Returns
        -------
        additional: list of :py:class:`~.DNS_Resource`
            the list of DNS additional records contained in the DNS PDU
        """
        cdef cpp_list[cppDNS.cppResource] adds = self.ptr.additional()
        return [
            DNS_Resource(bytes(add.dname()), bytes(add.data()), int(add.get_type()), int(add.query_class()), int(add.ttl()))
            for add in adds
        ]

    cpdef add_additional(self, DNS_Resource additional):
        """
        add_additional(additional)
        Add an additional resource record.

        Parameters
        ----------
        additional: :py:class:`~.DNS_Resource`
            the record to be added
        """
        if additional is None:
            return
        self.ptr.add_additional(additional.cpp_resource)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDNS(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDNS*> ptr


cpdef encode_domain_name(domain_name):
    """
    encode_domain_name(domain_name)
    """
    if not PyBytes_Check(domain_name):
        domain_name = bytes(domain_name)
    return <bytes>(cpp_encode_domain_name(<string>domain_name))
