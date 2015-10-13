# -*- coding: utf-8 -*-

cdef extern from "tins/loopback.h" namespace "Tins" nogil:
    PDUType loopback_pdu_flag "Tins::Loopback::pdu_flag"

    cppclass cppLoopback "Tins::Loopback" (cppPDU):
        cppLoopback()
        cppLoopback(const uint8_t *buf, uint32_t total_sz)
        uint32_t family() const
        void family(uint32_t family_id)
        void send(cppPacketSender &sender, const cppNetworkInterface &iface)      # if BSD

cdef class Loopback(PDU):
    cdef cppLoopback *ptr

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Loopback()
        obj = Loopback(_raw=True)
        obj.ptr = new cppLoopback(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppLoopback*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

    cpdef send(self, PacketSender sender, NetworkInterface iface)
