# -*- coding: utf-8 -*-
"""
RAW packet python class
"""

cdef factory_raw(cppPDU* ptr, uint8_t* buf, int size, object parent):
    if ptr is NULL and buf is NULL:
        return Raw()
    obj = Raw(_raw=True)
    obj.ptr = new cppRAW(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppRAW*> ptr
    obj.base_ptr = <cppPDU*> obj.ptr
    obj.parent = parent
    return obj

cdef class Raw(PDU):
    """
    Raw PDU packet
    """
    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if buf is None:
            buf = b""
        if isinstance(buf, bytes):
            self.ptr = new cppRAW(<const string>buf)
        elif isinstance(buf, bytearray):
            self.ptr = new cppRAW(<uint8_t*> buf, <uint32_t> len(buf))
        elif isinstance(buf, memoryview):
            # todo: check that buf has the right shape, etc
            self.ptr = new cppRAW(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
        elif isinstance(buf, cy_memoryview):
            # todo: check that buf has the right shape, etc
            self.ptr = new cppRAW(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
        else:
            raise ValueError("don't know what to do with type '%s'" % type(buf))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    property payload:
        def __get__(self):
            cdef vector[uint8_t] v = self.ptr.payload()
            cdef uint8_t* buf = &v[0]
            return <bytes>(buf[:v.size()])

        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* buf = <uint8_t*> (<bytes>value)
            cdef vector[uint8_t] v
            v.assign(buf, buf + len(value))
            self.ptr.payload(v)

    def __init__(self, buf=None, _raw=False):
        pass

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

cdef make_raw_from_const_uchar_buf(const uint8_t* buf, int size):
    if size == 0:
        raise ValueError("size can't be zero")
    if buf == NULL:
        raise ValueError("buf can't be a NULL pointer")
    return Raw(buf=make_mview_from_const_uchar_buf(buf, size))

cdef make_raw_from_uchar_buf(uint8_t* buf, int size):
    if size == 0:
        raise ValueError("size can't be zero")
    if buf == NULL:
        raise ValueError("buf can't be a NULL pointer")
    return Raw(buf=make_mview_from_uchar_buf(buf, size))

cpdef make_raw_from_typed_memoryview(unsigned char[:] data):
    if data is None:
        raise ValueError("data can't be None")
    return Raw(buf=<cy_memoryview> data)
