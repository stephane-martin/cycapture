# -*- coding: utf-8 -*-

cdef class IPReassembler(object):
    Status = IntEnum('IPReassemblerStatus', {
        'FRAGMENTED': TINS_FRAGMENTED,
        'NOT_FRAGMENTED': TINS_NOT_FRAGMENTED,
        'REASSEMBLED': TINS_REASSEMBLED
    })


    def __cinit__(self, callback=None):
        self.assembler = new IPv4Reassembler()

    def __dealloc(self):
        if self.assembler != NULL:
            del self.assembler

    def __init__(self, callback=None):
        self.py_callback = callback

    cpdef process(self, pdu):
        if not isinstance(pdu, PDU):
            raise TypeError
        cdef packet_status status = int(self.assembler.process((<PDU> pdu).base_ptr[0]))
        if status != IPReassembler.Status.FRAGMENTED and self.py_callback is not None:
            self.py_callback(pdu)
        return status

