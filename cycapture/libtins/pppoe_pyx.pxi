# -*- coding: utf-8 -*-

cdef class PPPoE(PDU):
    pdu_flag = PDU.PPPoE
    pdu_type = PDU.PPPoE

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != PPPoE:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppPPPoE()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppPPPoE(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppPPPoE* p = <cppPPPoE*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    property version:
        def __get__(self):
            return int(<uint8_t> self.ptr.version())
        def __set__(self, value):
            self.ptr.version(small_uint4(<uint8_t> int(value)))

    property type:
        def __get__(self):
            return int(<uint8_t> self.ptr.type())
        def __set__(self, value):
            self.ptr.type(small_uint4(<uint8_t> int(value)))

    property code:
        def __get__(self):
            return int(self.ptr.code())
        def __set__(self, value):
            self.ptr.code(<uint8_t> int(value))

    property session_id:
        def __get__(self):
            return int(self.ptr.session_id())
        def __set__(self, value):
            self.ptr.session_id(<uint16_t> int(value))

    property payload_length:
        def __get__(self):
            return int(self.ptr.payload_length())
        def __set__(self, value):
            self.ptr.payload_length(<uint16_t> int(value))

    property service_name:
        def __get__(self):
            try:
                return <bytes> (self.ptr.service_name())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.service_name(<string> (<bytes> value))

    property ac_name:
        def __get__(self):
            try:
                return <bytes> (self.ptr.ac_name())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.ac_name(<string> (<bytes> value))

    property service_name_error:
        def __get__(self):
            try:
                return <bytes> (self.ptr.service_name_error())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.service_name_error(<string> (<bytes> value))

    property ac_system_error:
        def __get__(self):
            try:
                return <bytes> (self.ptr.ac_system_error())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.ac_system_error(<string> (<bytes> value))

    property generic_error:
        def __get__(self):
            try:
                return <bytes> (self.ptr.generic_error())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.generic_error(<string> (<bytes> value))

    property host_uniq:
        def __get__(self):
            cdef vector[uint8_t] v = self.ptr.host_uniq()
            cdef uint8_t* p = &v[0]
            return <bytes> p[:v.size()]
        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* p = <uint8_t*> (<bytes> value)
            cdef vector[uint8_t] v
            v.assign(p, p + len(value))
            self.ptr.host_uniq(v)

    property ac_cookie:
        def __get__(self):
            cdef vector[uint8_t] v = self.ptr.ac_cookie()
            cdef uint8_t* p = &v[0]
            return <bytes> p[:v.size()]
        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* p = <uint8_t*> (<bytes> value)
            cdef vector[uint8_t] v
            v.assign(p, p + len(value))
            self.ptr.ac_cookie(v)

    property relay_session_id:
        def __get__(self):
            cdef vector[uint8_t] v = self.ptr.relay_session_id()
            cdef uint8_t* p = &v[0]
            return <bytes> p[:v.size()]
        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* p = <uint8_t*> (<bytes> value)
            cdef vector[uint8_t] v
            v.assign(p, p + len(value))
            self.ptr.relay_session_id(v)

    # todo: pppoe_vendor_spec_type vendor_specific() const -> make dict interface

    cpdef tags(self):
        pass
