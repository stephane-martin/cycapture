# -*- coding: utf-8 -*-
"""
ICMP packet python class
"""

cdef class ICMP(PDU):
    """
    ICMP packet
    """
    pdu_flag = PDU.ICMP
    pdu_type = PDU.ICMP

    ECHO_REPLY = ICMP_ECHO_REPLY
    DEST_UNREACHABLE = ICMP_DEST_UNREACHABLE
    SOURCE_QUENCH = ICMP_SOURCE_QUENCH
    REDIRECT = ICMP_REDIRECT
    ECHO_REQUEST = ICMP_ECHO_REQUEST
    TIME_EXCEEDED = ICMP_TIME_EXCEEDED
    PARAM_PROBLEM = ICMP_PARAM_PROBLEM
    TIMESTAMP_REQUEST = ICMP_TIMESTAMP_REQUEST
    TIMESTAMP_REPLY = ICMP_TIMESTAMP_REPLY
    INFO_REQUEST = ICMP_INFO_REQUEST
    INFO_REPLY = ICMP_INFO_REPLY
    ADDRESS_MASK_REQUEST = ICMP_ADDRESS_MASK_REQUEST
    ADDRESS_MASK_REPLY = ICMP_ADDRESS_MASK_REPLY

    FLAGS = Enum('FLAGS', {
        'ECHO_REPLY': ECHO_REPLY,
        'DEST_UNREACHABLE': DEST_UNREACHABLE,
        'SOURCE_QUENCH': SOURCE_QUENCH,
        'REDIRECT': REDIRECT,
        'ECHO_REQUEST': ECHO_REQUEST,
        'TIME_EXCEEDED': TIME_EXCEEDED,
        'PARAM_PROBLEM': PARAM_PROBLEM,
        'TIMESTAMP_REQUEST': TIMESTAMP_REQUEST,
        'TIMESTAMP_REPLY': TIMESTAMP_REPLY,
        'INFO_REQUEST': INFO_REQUEST,
        'INFO_REPLY': INFO_REPLY,
        'ADDRESS_MASK_REQUEST': ADDRESS_MASK_REQUEST,
        'ADDRESS_MASK_REPLY': ADDRESS_MASK_REPLY
    })

    FLAGS_VALUES = [flag.value for flag in FLAGS]

    def __cinit__(self, flag=None, buf=None, _raw=False):
        if _raw:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None and flag is None:
            self.ptr = new cppICMP()
        elif buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppICMP(buf_addr, size)
        elif isinstance(flag, int) and flag in ICMP.FLAGS_VALUES:
            self.ptr = new cppICMP(<ICMP_Flags> flag)
        elif isinstance(flag, ICMP.FLAGS):
            self.ptr = new cppICMP(<ICMP_Flags> flag.value)
        else:
            flag = int(flag)
            self.ptr = new cppICMP(<ICMP_Flags> flag)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, flag=None, buf=None, _raw=False):
        pass

    property checksum:
        def __get__(self):
            return self.ptr.checksum()

    property code:
        def __get__(self):
            return self.ptr.code()
        def __set__(self, value):
            self.ptr.code(<uint8_t> int(value))

    property icmp_type:
        def __get__(self):
            return self.ptr.get_type()
        def __set__(self, value):
            if isinstance(value, ICMP.FLAGS):
                value = value.value
            value = int(value)
            if value in ICMP.FLAGS_VALUES:
                self.ptr.set_type(<ICMP_Flags>value)
            else:
                raise ValueError("unknown ICMP flag type")

    property ident:
        def __get__(self):
            return self.ptr.ident()
        def __set__(self, value):
            self.ptr.ident(<uint16_t> value)

    property sequence:
        def __get__(self):
            return self.ptr.sequence()
        def __set__(self, value):
            self.ptr.sequence(<uint16_t> value)

    property mtu:
        def __get__(self):
            return self.ptr.mtu()
        def __set__(self, value):
            self.ptr.mtu(<uint16_t> value)

    property pointer:
        def __get__(self):
            return self.ptr.pointer()
        def __set__(self, value):
            self.ptr.pointer(<uint8_t> value)

    property original_timestamp:
        def __get__(self):
            return self.ptr.original_timestamp()
        def __set__(self, value):
            self.ptr.original_timestamp(<uint32_t> value)

    property receive_timestamp:
        def __get__(self):
            return self.ptr.receive_timestamp()
        def __set__(self, value):
            self.ptr.receive_timestamp(<uint32_t> value)

    property transmit_timestamp:
        def __get__(self):
            return self.ptr.transmit_timestamp()
        def __set__(self, value):
            self.ptr.transmit_timestamp(<uint32_t> value)

    property gateway:
        def __get__(self):
            cdef cppIPv4Address g = self.ptr.gateway()
            return IPv4Address.factory(&g)
        def __set__(self, value):
            addr = IPv4Address(value)
            self.ptr.gateway(<cppIPv4Address>(addr.ptr[0]))

    property address_mask:
        def __get__(self):
            cdef cppIPv4Address mask = self.ptr.address_mask()
            return IPv4Address.factory(&mask)
        def __set__(self, value):
            addr = IPv4Address(value)
            self.ptr.address_mask(<cppIPv4Address>(addr.ptr[0]))

    cpdef set_dest_unreachable(self):
        self.ptr.set_dest_unreachable()

    cpdef set_source_quench(self):
        self.ptr.set_source_quench()

    cpdef set_time_exceeded(self, flag=True):
        cdef cpp_bool b = 1 if flag else 0
        self.ptr.set_time_exceeded(b)

    cpdef set_param_problem(self, set_pointer=False, int bad_octet=0):
        cdef cpp_bool b = 1 if set_pointer else 0
        self.ptr.set_param_problem(b, <uint8_t> bad_octet)

    cpdef set_echo_request(self, int ident, int seq):
        self.ptr.set_echo_request(<uint16_t> ident, <uint16_t> seq)

    cpdef set_echo_reply(self, int ident, int seq):
        self.ptr.set_echo_reply(<uint16_t> ident, <uint16_t> seq)

    cpdef set_info_request(self, int ident, int seq):
        self.ptr.set_info_request(<uint16_t> ident, <uint16_t> seq)

    cpdef set_info_reply(self, int ident, int seq):
        self.ptr.set_info_reply(<uint16_t> ident, <uint16_t> seq)

    cpdef set_redirect(self, int code, address):
        addr = IPv4Address(address)
        self.ptr.set_redirect(<uint8_t> code, <cppIPv4Address>(addr.ptr[0]))

