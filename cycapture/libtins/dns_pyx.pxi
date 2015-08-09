
cdef factory_dns(cppPDU* ptr, uint8_t* buf, int size, object parent):
    if ptr is NULL and buf is NULL:
        return DNS()
    obj = DNS(_raw=True)
    obj.ptr = new cppDNS(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDNS*> ptr
    obj.base_ptr = <cppPDU*> obj.ptr
    obj.parent = parent
    return obj

cdef class DNS(PDU):
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

    IN = DNS_IN
    CH = DNS_CH
    HS = DNS_HS
    ANY = DNS_ANY

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        elif buf is None:
            self.ptr = new cppDNS()
        else:
            if PyBytes_Check(buf):
                self.ptr = new cppDNS(<uint8_t*> PyBytes_AS_STRING(buf), <uint32_t> PyBytes_Size(buf))
            elif isinstance(buf, bytearray):
                buf = memoryview(buf)
                self.ptr = new cppDNS(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            elif isinstance(buf, memoryview):
                if buf.itemsize == 1 and buf.ndim == 1:
                    self.ptr = new cppDNS(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
                else:
                    raise ValueError("the memoryview doesn't have the proper format")
            elif isinstance(buf, cy_memoryview):
                if buf.itemsize == 1 and buf.ndim == 1:
                    self.ptr = new cppDNS(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
                else:
                    raise ValueError("the typed memoryview doesn't have the proper format")
            else:
                raise ValueError("don't know what to do with type '%s'" % type(buf))

    def __init__(self, buf=None, _raw=False):
        pass

cpdef encode_domain_name(domain_name):
    if not PyBytes_Check(domain_name):
        domain_name = bytes(domain_name)
    return <bytes>(cpp_encode_domain_name(<string>domain_name))
