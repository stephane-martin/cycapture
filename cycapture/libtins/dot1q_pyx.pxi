# -*- coding: utf-8 -*-

cdef class Dot1Q(PDU):
    """
    IEEE 802.1q PDU class
    """
    pdu_flag = PDU.DOT1Q
    pdu_type = PDU.DOT1Q

    def __cinit__(self, tag_id=0, append_pad=True, _raw=False):
        if _raw is True or type(self) != Dot1Q:
            return

        tag_id = int(tag_id)
        append_pad = bool(append_pad)

        self.ptr = new cppDot1Q(small_uint12(<uint16_t> tag_id), <cpp_bool> append_pad)
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot1Q* p = <cppDot1Q*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, tag_id=0, append_pad=True):
        """
        __init__(tag_id=0, append_pad=True)

        Parameters
        ----------
        tag_id: uint16_t
            Tag VLAN ID
        append_pad: bool
            flag indicating whether padding will be appended at the end of this packet
        """


    property priority:
        """
        Priority field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(<uint8_t> self.ptr.priority())

        def __set__(self, value):
            value = int(value)
            self.ptr.priority(small_uint3(<uint8_t> value))

    property cfi:
        """
        Canonical Format Identifie field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(<uint8_t> self.ptr.cfi())

        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.cfi(small_uint1(<uint8_t> value))

    property id:
        """
        VLAN Id (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(<uint16_t> self.ptr.id())
        def __set__(self, value):
            self.ptr.id(small_uint12(<uint16_t> int(value)))

    property payload_type:
        """
        Payload type field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.payload_type())
        def __set__(self, value):
            self.ptr.payload_type(<uint16_t> int(value))

    property append_padding:
        """
        Flag indicating whether the appropriate padding will be at the end of the packet (read-write, `bool`).

        The flag could be set to ``False`` when two or more contiguous Dot1Q
        PDUs are added to a packet. In that case, only the Dot1Q that is
        closer to the link layer should add a padding at the end.
        """
        def __get__(self):
            return bool(self.ptr.append_padding())
        def __set__(self, value):
            value = bool(value)
            self.ptr.append_padding(<cpp_bool> value)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDot1Q(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDot1Q*> ptr

DOT1Q = Dot1Q
