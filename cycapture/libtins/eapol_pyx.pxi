# -*- coding: utf-8 -*-

cdef class EAPOL(PDU):
    """
    EAPOL abstract class
    """
    pdu_flag = PDU.EAPOL
    pdu_type = PDU.EAPOL

    Types = IntEnum("Types", {
        'RC4': EAPOL_RC4,
        'RSN': EAPOL_RSN,
        'EAPOL_WPA': EAPOL_EAPOL_WPA
    })

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
        if p is NULL:
            raise MalformedPacket
        return PDU.from_ptr(p, parent=None)

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

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != RC4EAPOL:
            return

        self.ptr = new cppRC4EAPOL()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppRC4EAPOL* p = <cppRC4EAPOL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    # noinspection PyMissingConstructor
    def __init__(self):
        """
        __init__()
        """

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

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppRC4EAPOL(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppRC4EAPOL*> ptr


cdef class RSNEAPOL(EAPOL):
    pdu_flag = PDU.RSNEAPOL
    pdu_type = PDU.RSNEAPOL

    key_iv_size = rsneapol_key_iv_size
    nonce_size = rsneapol_nonce_size
    mic_size = rsneapol_mic_size
    rsc_size = rsneapol_rsc_size
    id_size = rsneapol_id_size

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != RSNEAPOL:
            return

        self.ptr = new cppRSNEAPOL()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppRSNEAPOL* p = <cppRSNEAPOL*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    # noinspection PyMissingConstructor
    def __init__(self):
        """
        __init__()
        """

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

    property key:
        def __get__(self):
            cdef vector[uint8_t] k = (<cppRSNEAPOL*> self.ptr).key()
            return <bytes>((&(k[0]))[:k.size()])

        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* p = <uint8_t*> (<bytes> value)
            cdef vector[uint8_t] v
            v.assign(p, p + len(value))
            (<cppRSNEAPOL*> self.ptr).key(v)

    property key_iv:
        def __get__(self):
            cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).key_iv())
            return <bytes> p[:RSNEAPOL.key_iv_size]

        def __set__(self, value):
            value = bytes(value)[:RSNEAPOL.key_iv_size].ljust(RSNEAPOL.key_iv_size, '\x00')
            (<cppRSNEAPOL*> self.ptr).key_iv(<uint8_t*> (<bytes> value))

    property nonce:
        def __get__(self):
            cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).nonce())
            return <bytes> p[:RSNEAPOL.nonce_size]

        def __set__(self, value):
            value = bytes(value)[:RSNEAPOL.nonce_size].ljust(RSNEAPOL.nonce_size, '\x00')
            (<cppRSNEAPOL*> self.ptr).nonce(<uint8_t*> (<bytes> value))

    property rsc:
        def __get__(self):
            cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).rsc())
            return <bytes> p[:RSNEAPOL.rsc_size]

        def __set__(self, value):
            value = bytes(value)[:RSNEAPOL.rsc_size].ljust(RSNEAPOL.rsc_size, '\x00')
            (<cppRSNEAPOL*> self.ptr).rsc(<uint8_t*> (<bytes> value))

    property id:
        def __get__(self):
            cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).id())
            return <bytes> p[:RSNEAPOL.id_size]

        def __set__(self, value):
            value = bytes(value)[:RSNEAPOL.id_size].ljust(RSNEAPOL.id_size, '\x00')
            (<cppRSNEAPOL*> self.ptr).id(<uint8_t*> (<bytes> value))

    property mic:
        def __get__(self):
            cdef uint8_t* p = <uint8_t*> ((<cppRSNEAPOL*> self.ptr).mic())
            return <bytes> p[:RSNEAPOL.mic_size]

        def __set__(self, value):
            value = bytes(value)[:RSNEAPOL.mic_size].ljust(RSNEAPOL.mic_size, '\x00')
            (<cppRSNEAPOL*> self.ptr).mic(<uint8_t*> (<bytes> value))

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppRSNEAPOL(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppRSNEAPOL*> ptr

RC4_EAPOL = RC4EAPOL
RSN_EAPOL = RSNEAPOL
