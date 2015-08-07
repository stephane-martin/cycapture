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
        if PyBytes_Check(buf):
            self.ptr = new cppRAW(<uint8_t*> PyBytes_AS_STRING(buf), <uint32_t> PyBytes_Size(buf))
        elif isinstance(buf, bytearray):
            buf = memoryview(buf)
            self.ptr = new cppRAW(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
        elif isinstance(buf, memoryview):
            if buf.itemsize == 1 and buf.ndim == 1:
                self.ptr = new cppRAW(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            else:
                raise ValueError("the memoryview doesn't have the proper format")
        elif isinstance(buf, cy_memoryview):
            if buf.itemsize == 1 and buf.ndim == 1:
                self.ptr = new cppRAW(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
            else:
                raise ValueError("the typed memoryview doesn't have the proper format")
        else:
            raise ValueError("don't know what to do with type '%s'" % type(buf))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    property payload:
        def __get__(self):
            cdef const uint8_t* buf = &(self.ptr.payload()[0])
            cdef int size = self.ptr.payload().size()
            return <bytes>(buf[:size])

        def __set__(self, value):
            if not PyBytes_Check(value):
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

