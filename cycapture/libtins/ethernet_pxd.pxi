# -*- coding: utf-8 -*-

cdef extern from "tins/ethernetII.h" namespace "Tins" nogil:
    PDUType ethII_pdu_flag "Tins::EthernetII::pdu_flag"
    cppHWAddress6 ethII_BROADCAST "Tins::EthernetII::BROADCAST"

    cdef cppclass cppEthernetII "Tins::EthernetII" (cppPDU):
        cppEthernetII()
        cppEthernetII(const cppHWAddress6 &dst_hw_addr) except +custom_exception_handler
        cppEthernetII(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr) except +custom_exception_handler
        cppEthernetII(const unsigned char *buf, uint32_t total_sz) except +custom_exception_handler

        void send(cppPacketSender &sender, const cppNetworkInterface &iface) except +custom_exception_handler

        cppHWAddress6 dst_addr() const
        cppHWAddress6 src_addr() const
        uint16_t payload_type() const
        void dst_addr(const cppHWAddress6 &new_dst_addr)
        void src_addr(const cppHWAddress6 &new_src_addr)
        void payload_type(uint16_t new_payload_type)



cdef class EthernetII(PDU):
    cdef cppEthernetII* ptr
    cpdef send(self, PacketSender sender, NetworkInterface iface)





