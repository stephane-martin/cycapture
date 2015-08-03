# -*- coding: utf-8 -*-
"""
IP packet python class
"""
# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t
# noinspection PyUnresolvedReferences
from ..make_mview cimport make_mview_from_const_uchar_buf, make_mview_from_uchar_buf, mview_get_addr
# noinspection PyUnresolvedReferences
from cython.view cimport memoryview as cy_memoryview


cdef factory_ip(cppPDU* ptr, object parent):
    if ptr == NULL:
        raise ValueError("Can't make an IP object from a NULL pointer")
    obj = IP(_raw=True)
    obj.base_ptr = ptr
    obj.ptr = <cppIP*> ptr
    obj.parent = parent
    return obj


cdef class IP(PDU):
    """
    IP packet
    """
    pdu_flag = PDU.IP
    pdu_type = PDU.IP

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

    def __cinit__(self, dest_src_ips=None, buf=None, _raw=False):
        if _raw:
            return
        elif buf is None and dest_src_ips is None:
            self.ptr = new cppIP()
        elif buf is not None:
            # construct from a buffer
            if isinstance(buf, bytes):
                self.ptr = new cppIP(<uint8_t*> buf, <uint32_t> len(buf))
            elif isinstance(buf, bytearray):
                self.ptr = new cppIP(<uint8_t*> buf, <uint32_t> len(buf))
            elif isinstance(buf, memoryview):
                # todo: check that buf has the right shape, etc
                self.ptr = new cppIP(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            elif isinstance(buf, cy_memoryview):
                # todo: check that buf has the right shape, etc
                self.ptr = new cppIP(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
            else:
                raise ValueError("don't know what to do with type '%s'" % type(buf))
        elif isinstance(dest_src_ips, tuple) or isinstance(dest_src_ips, list):
            dest, src = dest_src_ips
            if src is None:
                src = IPv4Address()
            if dest is None:
                dest = IPv4Address()
            if not isinstance(src, IPv4Address):
                src = IPv4Address(src)
            if not isinstance(dest, IPv4Address):
                dest = IPv4Address(dest)
            self.ptr = new cppIP(<cppIPv4Address> ((<IPv4Address> src).ptr[0]), <cppIPv4Address> ((<IPv4Address> dest).ptr[0]))
        elif isinstance(dest_src_ips, IPv4Address):
            src = IPv4Address()
            dest = dest_src_ips
            self.ptr = new cppIP(<cppIPv4Address> ((<IPv4Address> src).ptr[0]), <cppIPv4Address> ((<IPv4Address> dest).ptr[0]))
        else:
            src = IPv4Address()
            dest = IPv4Address(dest_src_ips)
            self.ptr = new cppIP(<cppIPv4Address> ((<IPv4Address> src).ptr[0]), <cppIPv4Address> ((<IPv4Address> dest).ptr[0]))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dest_src_ips=None, buf=None, _raw=False):
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

