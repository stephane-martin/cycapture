# -*- coding: utf-8 -*-
"""
TCP packet python class
"""
# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t
# noinspection PyUnresolvedReferences
from ..make_mview cimport make_mview_from_const_uchar_buf, make_mview_from_uchar_buf, mview_get_addr
# noinspection PyUnresolvedReferences
from cython.view cimport memoryview as cy_memoryview


cdef factory_tcp(cppPDU* ptr, object parent):
    if ptr == NULL:
        raise ValueError("Can't make an IP object from a NULL pointer")
    obj = TCP(_raw=True)
    obj.base_ptr = ptr
    obj.ptr = <cppTCP*> ptr
    obj.parent = parent
    return obj


cdef class TCP(PDU):
    """
    TCP packet
    """
    pdu_flag = PDU.TCP
    pdu_type = PDU.TCP

    FIN = TCP_FIN
    SYN = TCP_SYN
    RST = TCP_RST
    PSH = TCP_PSH
    ACK = TCP_ACK
    URG = TCP_URG
    ECE = TCP_ECE
    CWR = TCP_CWR

    EOL = TCP_EOL
    NOP = TCP_NOP
    MSS = TCP_MSS
    WSCALE = TCP_WSCALE
    SACK_OK = TCP_SACK_OK
    SACK = TCP_SACK
    TSOPT = TCP_TSOPT
    ALTCHK = TCP_ALTCHK

    CHK_TCP = TCP_CHK_TCP
    CHK_8FLETCHER = TCP_CHK_8FLETCHER
    CHK_16FLETCHER = TCP_CHK_16FLETCHER

    def __cinit__(self, dest_src_ports=None, buf=None, _raw=False):
        if _raw:
            return
        elif buf is None and dest_src_ports is None:
            self.ptr = new cppTCP()
        elif buf is not None:
            # construct from a buffer
            if isinstance(buf, bytes):
                self.ptr = new cppTCP(<uint8_t*> buf, <uint32_t> len(buf))
            elif isinstance(buf, bytearray):
                self.ptr = new cppTCP(<uint8_t*> buf, <uint32_t> len(buf))
            elif isinstance(buf, memoryview):
                # todo: check that buf has the right shape, etc
                self.ptr = new cppTCP(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            elif isinstance(buf, cy_memoryview):
                # todo: check that buf has the right shape, etc
                self.ptr = new cppTCP(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
            else:
                raise ValueError("don't know what to do with type '%s'" % type(buf))
        elif isinstance(dest_src_ports, tuple) or isinstance(dest_src_ports, list):
            dest, src = dest_src_ports
            if src is None:
                src = 0
            if dest is None:
                dest = 0
            src = int(src)
            dest = int(dest)
            self.ptr = new cppTCP(<uint16_t>dest, <uint16_t>src)
        else:
            src = 0
            dest = int(dest_src_ports)
            self.ptr = new cppTCP(<uint16_t>dest, <uint16_t>src)
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dest_src_ports=None, buf=None, _raw=False):
        pass

    property sport:
        def __get__(self):
            return int(self.ptr.sport())
        def __set__(self, value):
            self.ptr.sport(<uint16_t> int(value))

    property dport:
        def __get__(self):
            return int(self.ptr.dport())
        def __set__(self, value):
            self.ptr.dport(<uint16_t> int(value))


cdef make_TCP_from_const_uchar_buf(const uint8_t* buf, int size):
    if size == 0:
        raise ValueError("size can't be zero")
    if buf == NULL:
        raise ValueError("buf can't be a NULL pointer")
    return TCP(buf=make_mview_from_const_uchar_buf(buf, size))

cdef make_TCP_from_uchar_buf(uint8_t* buf, int size):
    if size == 0:
        raise ValueError("size can't be zero")
    if buf == NULL:
        raise ValueError("buf can't be a NULL pointer")
    return TCP(buf=make_mview_from_uchar_buf(buf, size))

cpdef make_TCP_from_typed_memoryview(unsigned char[:] data):
    if data is None:
        raise ValueError("data can't be None")
    return TCP(buf=<cy_memoryview> data)
