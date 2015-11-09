# -*- coding: utf-8 -*-

cdef extern from "tins/eapol.h" namespace "Tins" nogil:

    PDUType eapol_pdu_flag "Tins::EAPOL::pdu_flag"
    PDUType rc4eapol_pdu_flag "Tins::RC4EAPOL::pdu_flag"
    PDUType rsneapol_pdu_flag "Tins::RSNEAPOL::pdu_flag"

    size_t rc4eapol_key_iv_size "Tins::RC4EAPOL::key_iv_size"
    size_t rc4eapol_key_sign_size "Tins::RC4EAPOL::key_sign_size"

    size_t rsneapol_key_iv_size "Tins::RSNEAPOL::key_iv_size"
    size_t rsneapol_nonce_size "Tins::RSNEAPOL::nonce_size"
    size_t rsneapol_mic_size "Tins::RSNEAPOL::mic_size"
    size_t rsneapol_rsc_size "Tins::RSNEAPOL::rsc_size"
    size_t rsneapol_id_size "Tins::RSNEAPOL::id_size"

    enum EAPOLTYPE "Tins::EAPOL::EAPOLTYPE":
        EAPOL_RC4 "Tins::EAPOL::RC4",
        EAPOL_RSN "Tins::EAPOL::RSN",
        EAPOL_EAPOL_WPA "Tins::EAPOL::EAPOL_WPA"

    # Note: allocate a cppEAPOL* with 'new' -> careful with memory management
    cppEAPOL* eapol_from_bytes "Tins::EAPOL::from_bytes" (const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

    cppclass cppEAPOL "Tins::EAPOL" (cppPDU):
        uint8_t version() const
        uint8_t packet_type() const
        uint16_t length() const
        uint8_t type() const

        void version(uint8_t new_version)
        void packet_type(uint8_t new_ptype)
        void length(uint16_t new_length)
        void type(uint8_t new_type)

    cppclass cppRC4EAPOL "Tins::RC4EAPOL" (cppEAPOL):
        cppRC4EAPOL()
        cppRC4EAPOL(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        uint16_t key_length() const
        uint64_t replay_counter() const
        const uint8_t *key_iv() const
        small_uint1 key_flag() const
        small_uint7 key_index() const
        const uint8_t *key_sign() const
        const vector[uint8_t] &key() const

        void key_length(uint16_t new_key_length)
        void replay_counter(uint64_t new_replay_counter)
        void key_iv(const uint8_t *new_key_iv)
        void key_flag(small_uint1 new_key_flag)
        void key_index(small_uint7 new_key_index)
        void key_sign(const uint8_t *new_key_sign)
        void key(const vector[uint8_t] &new_key)

    cppclass cppRSNEAPOL "Tins::RSNEAPOL" (cppEAPOL):
        cppRSNEAPOL()
        cppRSNEAPOL(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        uint16_t key_length() const
        uint64_t replay_counter() const
        const uint8_t *key_iv() const
        const uint8_t *nonce() const
        const uint8_t *rsc() const
        const uint8_t *id() const
        const uint8_t *mic() const
        uint16_t wpa_length() const
        const vector[uint8_t] &key() const
        small_uint1 key_mic() const
        small_uint1 secure() const
        small_uint1 error() const
        small_uint1 request() const
        small_uint1 encrypted() const
        small_uint3 key_descriptor() const
        small_uint1 key_t() const
        small_uint2 key_index() const
        small_uint1 install() const
        small_uint1 key_ack() const

        void key_length(uint16_t new_key_length)                #
        void replay_counter(uint64_t new_replay_counter)        #
        void key_iv(const uint8_t *new_key_iv)
        void nonce(const uint8_t *new_nonce)
        void rsc(const uint8_t *new_rsc)
        void id(const uint8_t *new_id)
        void mic(const uint8_t *new_mic)
        void wpa_length(uint16_t new_wpa_length)                #
        void key(const vector[uint8_t] &new_key)                #
        void key_mic(small_uint1 new_key_mic)                   #
        void secure(small_uint1 new_secure)                     #
        void error(small_uint1 new_error)                       #
        void request(small_uint1 new_request)                   #
        void encrypted(small_uint1 new_encrypted)               #
        void key_descriptor(small_uint3 new_key_descriptor)     #
        void key_t(small_uint1 new_key_t)                       #
        void key_index(small_uint2 new_key_index)               #
        void install(small_uint1 new_install)                   #
        void key_ack(small_uint1 new_key_ack)                   #

cdef class EAPOL(PDU):
    cdef cppEAPOL* ptr

    @staticmethod
    cdef c_from_bytes(uint8_t* buf_addr, uint32_t size)

cdef class RC4EAPOL(EAPOL):
    pass

cdef class RSNEAPOL(EAPOL):
    pass
