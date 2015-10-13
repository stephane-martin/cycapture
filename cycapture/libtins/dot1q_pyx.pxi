# -*- coding: utf-8 -*-

cdef class Dot1Q(PDU):
    pdu_flag = PDU.DOT1Q
    pdu_type = PDU.DOT1Q

    def __cinit__(self, tag_id=0, append_pad=True, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot1Q:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            tag_id = int(tag_id)
            append_pad = bool(append_pad)
            self.ptr = new cppDot1Q(small_uint12(<uint16_t> tag_id), <cpp_bool> append_pad)
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot1Q(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot1Q* p = <cppDot1Q*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    property priority:
        def __get__(self):
            return int(<uint8_t> self.ptr.priority())

        def __set__(self, value):
            value = int(value)
            self.ptr.priority(small_uint3(<uint8_t> value))

    property cfi:
        def __get__(self):
            return int(<uint8_t> self.ptr.cfi())

        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.cfi(small_uint1(<uint8_t> value))

    property id:
        def __get__(self):
            return int(<uint16_t> self.ptr.id())
        def __set__(self, value):
            self.ptr.id(small_uint12(<uint16_t> int(value)))

    property payload_type:
        def __get__(self):
            return int(self.ptr.payload_type())
        def __set__(self, value):
            self.ptr.payload_type(<uint16_t> int(value))

    property append_padding:
        def __get__(self):
            return bool(self.ptr.append_padding())
        def __set__(self, value):
            value = bool(value)
            self.ptr.append_padding(<cpp_bool> value)
