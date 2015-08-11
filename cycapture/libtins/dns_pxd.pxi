# -*- coding: utf-8 -*-

cdef extern from "tins/dns.h" namespace "Tins" nogil:
    PDUType dns_pdu_flag "Tins::DNS::pdu_flag"
    enum QRType "Tins::DNS::QRType":
        DNS_QUERY "Tins::DNS::QUERY",
        DNS_RESPONSE "Tins::DNS::RESPONSE"
    enum QueryType "Tins::DNS::QueryType":
        DNS_A "Tins::DNS::A",
        DNS_NS "Tins::DNS::NS",
        DNS_MD "Tins::DNS::MD",
        DNS_MF "Tins::DNS::MF",
        DNS_CNAME "Tins::DNS::CNAME",
        DNS_SOA "Tins::DNS::SOA",
        DNS_MB "Tins::DNS::MB",
        DNS_MG "Tins::DNS::MG",
        DNS_MR "Tins::DNS::MR",
        DNS_NULL_R "Tins::DNS::NULL_R",
        DNS_WKS "Tins::DNS::WKS",
        DNS_PTR "Tins::DNS::PTR",
        DNS_HINFO "Tins::DNS::HINFO",
        DNS_MINFO "Tins::DNS::MINFO",
        DNS_MX "Tins::DNS::MX",
        DNS_TXT "Tins::DNS::TXT",
        DNS_RP "Tins::DNS::RP",
        DNS_AFSDB "Tins::DNS::AFSDB",
        DNS_X25 "Tins::DNS::X25",
        DNS_ISDN "Tins::DNS::ISDN",
        DNS_RT "Tins::DNS::RT",
        DNS_NSAP "Tins::DNS::NSAP",
        DNS_NSAP_PTR "Tins::DNS::NSAP_PTR",
        DNS_SIG "Tins::DNS::SIG",
        DNS_KEY "Tins::DNS::KEY",
        DNS_PX "Tins::DNS::PX",
        DNS_GPOS "Tins::DNS::GPOS",
        DNS_AAAA "Tins::DNS::AAAA",
        DNS_LOC "Tins::DNS::LOC",
        DNS_NXT "Tins::DNS::NXT",
        DNS_EID "Tins::DNS::EID",
        DNS_NIMLOC "Tins::DNS::NIMLOC",
        DNS_SRV "Tins::DNS::SRV",
        DNS_ATMA "Tins::DNS::ATMA",
        DNS_NAPTR "Tins::DNS::NAPTR",
        DNS_KX "Tins::DNS::KX",
        DNS_CERT "Tins::DNS::CERT",
        DNS_A6 "Tins::DNS::A6",
        DNS_DNAM "Tins::DNS::DNAM",
        DNS_SINK "Tins::DNS::SINK",
        DNS_OPT "Tins::DNS::OPT",
        DNS_APL "Tins::DNS::APL",
        DNS_DS "Tins::DNS::DS",
        DNS_SSHFP "Tins::DNS::SSHFP",
        DNS_IPSECKEY "Tins::DNS::IPSECKEY",
        DNS_RRSIG "Tins::DNS::RRSIG",
        DNS_NSEC "Tins::DNS::NSEC",
        DNS_DNSKEY "Tins::DNS::DNSKEY",
        DNS_DHCID "Tins::DNS::DHCID",
        DNS_NSEC3 "Tins::DNS::NSEC3",
        DNS_NSEC3PARAM "Tins::DNS::NSEC3PARAM"

    enum QueryClass "Tins::DNS::QueryClass":
        DNS_IN "Tins::DNS::IN",
        DNS_CH "Tins::DNS::CH",
        DNS_HS "Tins::DNS::HS",
        DNS_ANY "Tins::DNS::ANY"

    cdef cppclass cppDNS "Tins::DNS" (cppPDU):
        PDUType pdu_type() const

        cppclass Query:
            Query(const string &nm, QueryType tp, QueryClass cl)
            Query()

            const string &dname() const
            void dname(const string &nm)
            QueryType get_type "type"() const
            void set_type "type"(QueryType tp)
            QueryClass query_class() const
            void query_class(QueryClass cl)

        cppclass Resource:
            Resource(const string &dname, const string &data, uint16_t t, uint16_t rclass, uint32_t ttl)
            Resource()

            const string &dname() const
            void dname(const string &data)
            const string &data() const
            void data(const string &data)
            uint16_t get_type "type"() const
            void set_type "type"(uint16_t data)
            uint16_t query_class() const
            void query_class(uint16_t data)
            uint32_t ttl() const
            void ttl(uint16_t data)

        #typedef std::list<Query> queries_type;
        #typedef std::list<Resource> resources_type;
        #typedef IPv4Address address_type;
        #typedef IPv6Address address_v6_type;

        cppDNS()
        cppDNS(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        uint16_t ident "id"() const
        void ident "id"(uint16_t new_id)
        QRType get_type "type"() const
        void set_type "type"(QRType new_qr)
        uint8_t opcode() const
        void opcode(uint8_t new_opcode)
        uint8_t authoritative_answer() const
        void authoritative_answer(uint8_t new_aa)
        uint8_t truncated() const
        void truncated(uint8_t new_tc)
        uint8_t recursion_desired() const
        void recursion_desired(uint8_t new_rd)
        uint8_t recursion_available() const
        void recursion_available(uint8_t new_ra)
        uint8_t z() const
        void z(uint8_t new_z)
        uint8_t authenticated_data() const
        void authenticated_data(uint8_t new_ad)
        uint8_t checking_disabled() const
        void checking_disabled(uint8_t new_cd)
        uint8_t rcode() const
        void rcode(uint8_t new_rcode)
        uint16_t questions_count() const
        uint16_t answers_count() const
        uint16_t authority_count() const
        uint16_t additional_count() const

        cpp_list[Query] queries() const
        void add_query(const Query &query)
        cpp_list[Resource] answers() const
        void add_answer(const Resource &resource)
        cpp_list[Resource] authority() const
        void add_authority(const Resource &resource)
        cpp_list[Resource] additional() const
        void add_additional(const Resource &resource)

    cdef string cpp_encode_domain_name "Tins::DNS::encode_domain_name"(const string &domain_name)

cdef factory_dns(cppPDU* ptr, uint8_t* buf, int size, object parent)

cdef class DNS(PDU):
    cdef cppDNS* ptr

cpdef encode_domain_name(domain_name)
