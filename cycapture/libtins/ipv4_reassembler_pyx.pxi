# -*- coding: utf-8 -*-

cdef class IPReassembler(object):
    FRAGMENTED = TINS_FRAGMENTED
    NOT_FRAGMENTED = TINS_NOT_FRAGMENTED
    REASSEMBLED = TINS_REASSEMBLED

    def __cinit__(self, callback=None):
        self.assembler = new IPv4Reassembler()

    def __dealloc(self):
        if self.assembler != NULL:
            del self.assembler

    def __init__(self, callback=None):
        self.py_callback = callback

    cpdef feed(self, PDU pdu):
        if pdu is None:
            return None
        cdef packet_status status = self.assembler.process(pdu.base_ptr[0])
        if status != self.FRAGMENTED:
            if self.py_callback is not None:
                self.py_callback(pdu)
            return pdu
        return None

