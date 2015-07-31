# -*- coding: utf-8 -*-
# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t
# noinspection PyUnresolvedReferences
from ..make_mview cimport make_mview_from_const_uchar_buf, make_mview_from_uchar_buf, mview_get_addr
# noinspection PyUnresolvedReferences
from cython.view cimport memoryview as cy_memoryview

cdef class IP(object):
    """
    IP packet
    """
    CONTROL = IP_OPT_CLASS_CONTROL
    MEASUREMENT = IP_OPT_CLASS_MEASUREMENT
    END = IP_OPT_NUMBER_END
    NOOP = IP_OPT_NUMBER_NOOP
    SEC = IP_OPT_NUMBER_SEC
    LSSR = IP_OPT_NUMBER_LSSR
    TIMESTAMP = IP_OPT_NUMBER_TIMESTAMP
    EXTSEC = IP_OPT_NUMBER_EXTSEC
    RR = IP_OPT_NUMBER_RR
    SID = IP_OPT_NUMBER_SID
    SSRR = IP_OPT_NUMBER_SSRR
    MTUPROBE = IP_OPT_NUMBER_MTUPROBE
    MTUREPLY = IP_OPT_NUMBER_MTUREPLY
    EIP = IP_OPT_NUMBER_EIP
    TR = IP_OPT_NUMBER_TR
    ADDEXT = IP_OPT_NUMBER_ADDEXT
    RTRALT = IP_OPT_NUMBER_RTRALT
    SDB = IP_OPT_NUMBER_SDB
    DPS = IP_OPT_NUMBER_DPS
    UMP = IP_OPT_NUMBER_UMP
    QS = IP_OPT_NUMBER_QS

    def __cinit__(self, buf=None, src_dest=None):
        cdef void* p
        if buf is None and src_dest is None:
            self.ptr = new cppIP()
        elif buf is not None:
            # construct from a buffer
            if isinstance(buf, bytes):
                self.ptr = new cppIP(<uint8_t*> buf, <uint32_t> len(buf))
            elif isinstance(buf, bytearray):
                self.ptr = new cppIP(<uint8_t*> buf, <uint32_t> len(buf))
            elif isinstance(buf, memoryview):
                # todo: check that buf has the right shape, etc
                p = mview_get_addr(<void*> buf)
                self.ptr = new cppIP(<uint8_t*> p, len(buf))
            elif isinstance(buf, cy_memoryview):
                # todo: check that buf has the right shape, etc
                self.ptr = new cppIP(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
            else:
                raise ValueError("don't know what to do with type '%s'" % type(buf))
            pass
        else:
            # todo: build from src and dest IPv4 addresses
            src, dest = src_dest
            if src is None:
                src = IPv4Address()
            if dest is None:
                dest = IPv4Address()
            if not isinstance(src, IPv4Address):
                src = IPv4Address(src)
            if not isinstance(dest, IPv4Address):
                dest = IPv4Address(dest)

            self.ptr = new cppIP(<cppIPv4Address> ((<IPv4Address> src).ptr[0]), <cppIPv4Address> ((<IPv4Address> dest).ptr[0]))

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __init__(self, buf=None, src_dest=None):
        pass

    cpdef eol(self):
        pass

    cpdef noop(self):
        pass



cdef make_IP_from_const_uchar_buf(const uint8_t* buf, int size):
    if size == 0:
        raise ValueError("size can't be zero")
    if buf == NULL:
        raise ValueError("buf can't be a NULL pointer")
    return IP(buf=make_mview_from_const_uchar_buf(buf, size))

cdef make_IP_from_uchar_buf(uint8_t* buf, int size):
    if size == 0:
        raise ValueError("size can't be zero")
    if buf == NULL:
        raise ValueError("buf can't be a NULL pointer")
    return IP(buf=make_mview_from_uchar_buf(buf, size))

cpdef make_IP_from_typed_memoryview(unsigned char[:] data):
    if data is None:
        raise ValueError("data can't be None")
    return IP(buf=<cy_memoryview> data)

