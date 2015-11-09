# -*- coding: utf-8 -*-
"""
ICMP packet python class
"""

cdef class ICMP(PDU):
    """
    ICMP packet.

    Instances of this class must be sent over a level 3 PDU.
    """
    pdu_flag = PDU.ICMP
    pdu_type = PDU.ICMP

    Flags = make_enum('ICMP_Flags', 'Flags', 'ICMP flags', {
        'ECHO_REPLY': ICMP_ECHO_REPLY,
        'DEST_UNREACHABLE': ICMP_DEST_UNREACHABLE,
        'SOURCE_QUENCH': ICMP_SOURCE_QUENCH,
        'REDIRECT': ICMP_REDIRECT,
        'ECHO_REQUEST': ICMP_ECHO_REQUEST,
        'TIME_EXCEEDED': ICMP_TIME_EXCEEDED,
        'PARAM_PROBLEM': ICMP_PARAM_PROBLEM,
        'TIMESTAMP_REQUEST': ICMP_TIMESTAMP_REQUEST,
        'TIMESTAMP_REPLY': ICMP_TIMESTAMP_REPLY,
        'INFO_REQUEST': ICMP_INFO_REQUEST,
        'INFO_REPLY': ICMP_INFO_REPLY,
        'ADDRESS_MASK_REQUEST': ICMP_ADDRESS_MASK_REQUEST,
        'ADDRESS_MASK_REPLY': ICMP_ADDRESS_MASK_REPLY
    })


    def __cinit__(self, flag=None, _raw=False):
        if _raw:
            return

        if flag is None:
            self.ptr = new cppICMP()
        else:
            self.ptr = new cppICMP(ICMP.Flags(int(flag)))

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, flag=None):
        """
        __init__(flag=None)
        Parameters
        ----------
        flag: int or :py:class:`~.ICMP.Flags`
            The type flag which will be set (`ECHO_REQUEST` if none provided)
        """

    property checksum:
        """
        The checksum field (read-only)
        """
        def __get__(self):
            return self.ptr.checksum()

    property code:
        """
        Code field (read-write, `uint8_t`)
        """
        def __get__(self):
            return self.ptr.code()
        def __set__(self, value):
            self.ptr.code(<uint8_t> int(value))

    property type:
        """
        Type field (read-write, :py:class:`~.ICMP.Flags`
        """
        def __get__(self):
            return self.ptr.get_type()

        def __set__(self, value):
            value = ICMP.Flags(value)
            self.ptr.set_type(<ICMP_Flags>value)

    property id:
        """
        Id field (read-write, `uint16_t`)
        """
        def __get__(self):
            return self.ptr.ident()
        def __set__(self, value):
            self.ptr.ident(<uint16_t> value)

    property sequence:
        """
        Sequence field (read-write, `uint16_t`)
        """
        def __get__(self):
            return self.ptr.sequence()
        def __set__(self, value):
            self.ptr.sequence(<uint16_t> value)

    property mtu:
        """
        MTU field (read-write, `uint16_t`)
        """
        def __get__(self):
            return self.ptr.mtu()
        def __set__(self, value):
            self.ptr.mtu(<uint16_t> value)

    property pointer:
        """
        Pointer field (read-write, `uint8_t`)
        """
        def __get__(self):
            return self.ptr.pointer()
        def __set__(self, value):
            self.ptr.pointer(<uint8_t> value)

    property original_timestamp:
        """
        Original timestamp field (read-write, `uint32_t`)
        """
        def __get__(self):
            return self.ptr.original_timestamp()
        def __set__(self, value):
            self.ptr.original_timestamp(<uint32_t> value)

    property receive_timestamp:
        """
        Receive timestamp field (read-write, `uint32_t`)
        """
        def __get__(self):
            return self.ptr.receive_timestamp()
        def __set__(self, value):
            self.ptr.receive_timestamp(<uint32_t> value)

    property transmit_timestamp:
        """
        Transmit timestamp field (read-write, `uint32_t`)
        """
        def __get__(self):
            return self.ptr.transmit_timestamp()
        def __set__(self, value):
            self.ptr.transmit_timestamp(<uint32_t> value)

    property gateway:
        """
        Gateway field (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            cdef cppIPv4Address g = self.ptr.gateway()
            return IPv4Address.factory(&g)
        def __set__(self, value):
            addr = IPv4Address(value)
            self.ptr.gateway(<cppIPv4Address>(addr.ptr[0]))

    property address_mask:
        """
        Address mask field (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            cdef cppIPv4Address mask = self.ptr.address_mask()
            return IPv4Address.factory(&mask)
        def __set__(self, value):
            addr = IPv4Address(value)
            self.ptr.address_mask(<cppIPv4Address>(addr.ptr[0]))

    cpdef set_dest_unreachable(self):
        """
        set_dest_unreachable()
        Sets `destination unreachable` for this PDU.
        """
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



    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppICMP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppICMP*> ptr
