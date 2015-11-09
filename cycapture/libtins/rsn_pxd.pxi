# -*- coding: utf-8 -*-

cdef extern from "tins/rsn_information.h" namespace "Tins" nogil:

    # typedef std::vector<CypherSuites> cyphers_type;
    # typedef std::vector<AKMSuites> akm_type;
    # typedef std::vector<uint8_t> serialization_type;

    ctypedef enum RSN_CypherSuites "Tins::RSNInformation::CypherSuites":
        RSN_WEP_40 "Tins::RSNInformation::WEP_40",
        RSN_TKIP "Tins::RSNInformation::TKIP",
        RSN_CCMP "Tins::RSNInformation::CCMP",
        RSN_WEP_104 "Tins::RSNInformation::WEP_104"

    ctypedef enum RSN_AKMSuites "Tins::RSNInformation::AKMSuites":
        RSN_PMKSA "Tins::RSNInformation::PMKSA",
        RSN_PSK "Tins::RSNInformation::PSK"


    cppclass cppRSNInformation "Tins::RSNInformation":
        cppRSNInformation()
        cppRSNInformation(const vector[uint8_t] &buf)
        cppRSNInformation(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler
        void add_pairwise_cypher(RSN_CypherSuites cypher)
        void add_akm_cypher(RSN_AKMSuites akm)
        RSN_CypherSuites group_suite()
        void group_suite(RSN_CypherSuites group)
        uint16_t version()
        void version(uint16_t ver)
        uint16_t capabilities()
        void capabilities(uint16_t cap)
        vector[RSN_CypherSuites] &pairwise_cyphers()
        vector[RSN_AKMSuites] &akm_cyphers()
        vector[uint8_t] serialize()

    cppRSNInformation RSN_from_option "Tins::RSNInformation::from_option" (const dot11_pdu_option& opt)
    cppRSNInformation RSN_wpa2_psk "Tins::RSNInformation::wpa2_psk" ()

cdef class RSNInformation(object):
    cdef cppRSNInformation* ptr
    cpdef add_pairwise_cypher(self, cypher)
    cpdef add_akm_cypher(self, akm)
    cpdef get_pairwise_cyphers(self)
    cpdef get_akm_cyphers(self)
    cpdef serialize(self)

    @staticmethod
    cdef factory(cppRSNInformation* info)

