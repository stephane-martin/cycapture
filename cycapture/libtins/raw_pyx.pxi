# -*- coding: utf-8 -*-
"""
RAW packet python class
"""



cdef class RAW(PDU):
    """
    RAW PDU packet
    """
    pdu_flag = PDU.RAW
    pdu_type = PDU.RAW

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if buf is None:
            buf = b""
        cdef uint8_t* buf_addr
        cdef uint32_t size
        PDU.prepare_buf_arg(buf, &buf_addr, &size)
        self.ptr = new cppRAW(buf_addr, size)
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

    cpdef to(self, obj):
        cdef int t
        if isinstance(obj, type):
            if not hasattr(obj, "pdu_type"):
                raise ValueError("Don't know what to to with: %s (no attribute pdu_type)" % obj.__name__)
            if obj.pdu_type < 0:
                raise ValueError("Don't know what to to with: %s (pdu_type attr is negative)" % obj.__name__)
            t = obj.pdu_type
        elif isinstance(obj, bytes):
            obj = (<bytes> obj).lower()
            try:
                t = map_classname_to_pdutype.at(<string>obj)
            except IndexError:
                raise TypeError("There is no PDU called: %s" % obj)
        else:
            t = int(obj)
        # the factory uses a copy of self's data (via buf), so we don't need to set af parent for the returned object
        return (map_classname_to_factory[map_pdutype_to_classname[t]])(NULL, &(self.ptr.payload()[0]), self.ptr.payload().size(), None)
        # (cppPDU* ptr, uint8_t* buf, int size, object parent)

    def __init__(self, buf=None, _raw=False):
        pass

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

