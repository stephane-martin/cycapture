# -*- coding: utf-8 -*-

cdef class UDP(PDU):
    """
    Encapsulate an UDP PDU.

    While sniffing, the payload sent in each packet will be wrapped in a RAW PDU::

        >>> from cycapture.libtins import UDP, RAW
        >>> buf = ...
        >>> pdu = UDP.from_buffer(buf)
        >>> raw = pdu.rfind_pdu(RAW)
        >>> payload = raw.payload
    """
    pdu_flag = PDU.UDP
    pdu_type = PDU.UDP

    def __cinit__(self, dport=0, sport=0, _raw=False):
        if _raw:
            return

        if dport is None:
            dport = 0
        if sport is None:
            sport = 0

        self.ptr = new cppUDP(<uint16_t> int(dport), <uint16_t> int(sport))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dport=0, sport=0):
        """
        __init__(dport=0, sport=0)

        Parameters
        ----------
        dport: uint16_t
            destination port
        sport: uint16_t
            source port
        """
        pass

    property sport:
        """
        Source port (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.sport())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.sport(<uint16_t> int(value))

    property dport:
        """
        Destination port (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.dport())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.dport(<uint16_t> int(value))

    property length:
        """
        Length of the datagram (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.length())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.length(<uint16_t> int(value))

    property checksum:
        """
        checksum of the datagram (read-only)
        """
        def __get__(self):
            return int(self.ptr.checksum())


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppUDP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppUDP*> ptr
