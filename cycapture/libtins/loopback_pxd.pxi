# -*- coding: utf-8 -*-

cdef extern from "tins/loopback.h" namespace "Tins" nogil:
    PDUType loopback_pdu_flag "Tins::Loopback::pdu_flag"

    cppclass cppLoopback "Tins::Loopback" (cppPDU):
        cppLoopback()
        cppLoopback(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler
        uint32_t family() const
        void family(uint32_t family_id)
        void send(cppPacketSender &sender, const cppNetworkInterface &iface)      # if BSD

cdef class Loopback(PDU):
    cdef cppLoopback *ptr
    cpdef send(self, PacketSender sender, NetworkInterface iface)
