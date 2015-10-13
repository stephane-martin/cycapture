# -*- coding: utf-8 -*-

cdef class EAPOL(PDU):
    pdu_flag = PDU.EAPOL
    pdu_type = PDU.EAPOL

    def __cinit__(self):
        pass

    def __init__(self):
        raise NotImplementedError

    def __dealloc__(self):
        pass

    @staticmethod
    def from_bytes(buf):
        if buf is None:
            raise ValueError("buf can't be None")
        cdef uint8_t* buf_addr
        cdef uint32_t size
        PDU.prepare_buf_arg(buf, &buf_addr, &size)
        return EAPOL.c_from_bytes(buf_addr, size)

    @staticmethod
    cdef c_from_bytes(uint8_t* buf_addr, uint32_t size):
        if buf_addr is NULL or size == 0:
            raise ValueError("buffer can't be empty")
        cdef cppEAPOL* p = eapol_from_bytes(buf_addr, size)         # equivalent to new
        cdef string classname
        if p is not NULL:
            classname = map_pdutype_to_classname[p.pdu_type()]
            return (map_classname_to_factory[classname])(p, NULL, 0, None)
        else:
            raise MalformedPacket

    property version:
        def __get__(self):
            return int((<cppEAPOL*> self.ptr).version())
        def __set__(self, value):
            (<cppEAPOL*> self.ptr).version(<uint8_t> int(value))

    property packet_type:
        def __get__(self):
            return int((<cppEAPOL*> self.ptr).packet_type())
        def __set__(self, value):
            (<cppEAPOL*> self.ptr).packet_type(<uint8_t> int(value))

    property length:
        def __get__(self):
            return int((<cppEAPOL*> self.ptr).length())
        def __set__(self, value):
            (<cppEAPOL*> self.ptr).length(<uint16_t> int(value))

    property type:
        def __get__(self):
            return int((<cppEAPOL*> self.ptr).type())
        def __set__(self, value):
            (<cppEAPOL*> self.ptr).type(<uint8_t> int(value))

cdef class RC4EAPOL(EAPOL):
    pdu_flag = PDU.RC4EAPOL
    pdu_type = PDU.RC4EAPOL

    key_iv_size = rc4eapol_key_iv_size
    key_sign_size = rc4eapol_key_sign_size

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != RC4EAPOL:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppRC4EAPOL()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppRC4EAPOL(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppRC4EAPOL* p = <cppRC4EAPOL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    property key_length:
        def __get__(self):
            return int((<cppRC4EAPOL*> self.ptr).key_length())
        def __set__(self, value):
            (<cppRC4EAPOL*> self.ptr).key_length(<uint16_t> int(value))

    property replay_counter:
        def __get__(self):
            return int((<cppRC4EAPOL*> self.ptr).replay_counter())
        def __set__(self, value):
            (<cppRC4EAPOL*> self.ptr).replay_counter(<uint64_t> int(value))

    property key_flag:
        def __get__(self):
            return bool(<uint8_t> ((<cppRC4EAPOL*> self.ptr).key_flag()))
        def __set__(self, value):
            cdef uint8_t v = 1 if value else 0
            (<cppRC4EAPOL*> self.ptr).key_flag(small_uint1(v))

    property key_index:
        def __get__(self):
            return int(<uint8_t> ((<cppRC4EAPOL*> self.ptr).key_index()))
        def __set__(self, value):
            (<cppRC4EAPOL*> self.ptr).key_index(small_uint7(<uint8_t>int(value)))

    property key:
        def __get__(self):
            cdef vector[uint8_t] k = (<cppRC4EAPOL*> self.ptr).key()
            return <bytes>((&(k[0]))[:k.size()])

        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* p = <uint8_t*> (<bytes> value)
            cdef vector[uint8_t] v
            v.assign(p, p + len(value))
            (<cppRC4EAPOL*> self.ptr).key(v)

    property key_iv:
        def __get__(self):
            cdef uint8_t* p = <uint8_t*> ((<cppRC4EAPOL*> self.ptr).key_iv())
            return <bytes> p[:RC4EAPOL.key_iv_size]

        def __set__(self, value):
            value = bytes(value)[:RC4EAPOL.key_iv_size].ljust(RC4EAPOL.key_iv_size, '\x00')
            (<cppRC4EAPOL*> self.ptr).key_iv(<uint8_t*> (<bytes> value))

    property key_sign:
        def __get__(self):
            cdef uint8_t* p = <uint8_t*> ((<cppRC4EAPOL*> self.ptr).key_sign())
            return <bytes> p[:RC4EAPOL.key_sign_size]

        def __set__(self, value):
            value = bytes(value)[:RC4EAPOL.key_sign_size].ljust(RC4EAPOL.key_sign_size, '\x00')
            (<cppRC4EAPOL*> self.ptr).key_sign(<uint8_t*> (<bytes> value))


cdef class RSNEAPOL(EAPOL):
    pdu_flag = PDU.RSNEAPOL
    pdu_type = PDU.RSNEAPOL

    key_iv_size = rsneapol_key_iv_size
    nonce_size = rsneapol_nonce_size
    mic_size = rsneapol_mic_size
    rsc_size = rsneapol_rsc_size
    id_size = rsneapol_id_size

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != RSNEAPOL:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppRSNEAPOL()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppRSNEAPOL(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppRSNEAPOL* p = <cppRSNEAPOL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass


    property key_length:
        def __get__(self):
            return int((<cppRSNEAPOL*> self.ptr).key_length())
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).key_length(<uint16_t> int(value))

    property replay_counter:
        def __get__(self):
            return int((<cppRSNEAPOL*> self.ptr).replay_counter())
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).replay_counter(<uint64_t> int(value))

    property wpa_length:
        def __get__(self):
            return int((<cppRSNEAPOL*> self.ptr).wpa_length())
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).wpa_length(<uint16_t> int(value))

    property key_mic:
        def __get__(self):
            return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_mic()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).key_mic(small_uint1(<uint8_t> bool(value)))

    property secure:
        def __get__(self):
            return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).secure()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).secure(small_uint1(<uint8_t> bool(value)))

    property error:
        def __get__(self):
            return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).error()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).error(small_uint1(<uint8_t> bool(value)))

    property request:
        def __get__(self):
            return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).request()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).request(small_uint1(<uint8_t> bool(value)))

    property encrypted:
        def __get__(self):
            return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).encrypted()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).encrypted(small_uint1(<uint8_t> bool(value)))

    property key_t:
        def __get__(self):
            return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_t()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).key_t(small_uint1(<uint8_t> bool(value)))

    property install:
        def __get__(self):
            return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).install()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).install(small_uint1(<uint8_t> bool(value)))

    property key_ack:
        def __get__(self):
            return bool(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_ack()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).key_ack(small_uint1(<uint8_t> bool(value)))

    property key_descriptor:
        def __get__(self):
            return int(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_descriptor()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).key_descriptor(small_uint3(<uint8_t> int(value)))

    property key_index:
        def __get__(self):
            return int(<uint8_t> ((<cppRSNEAPOL*> self.ptr).key_index()))
        def __set__(self, value):
            (<cppRSNEAPOL*> self.ptr).key_index(small_uint2(<uint8_t> int(value)))

