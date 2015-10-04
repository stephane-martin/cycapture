# -*- coding: utf-8 -*-

cdef extern from "tins/arp.h" namespace "Tins" nogil:
    PDUType arp_pdu_flag "Tins::ARP::pdu_flag"

    enum ARP_Flags "Tins::ARP::Flags":
        ARP_REQUEST "Tins::ARP::REQUEST",
        ARP_REPLY "Tins::ARP::REPLY"

    cppclass cppARP "Tins::ARP" (cppPDU):

        cppARP()
        cppARP(cppIPv4Address target_ip)
        cppARP(cppIPv4Address target_ip, cppIPv4Address sender_ip)
        cppARP(cppIPv4Address target_ip, cppIPv4Address sender_ip, const cppHWAddress6 &target_hw)
        cppARP(cppIPv4Address target_ip, cppIPv4Address sender_ip, const cppHWAddress6 &target_hw, const cppHWAddress6 &sender_hw)
        cppARP(const uint8_t *buf, uint32_t total_sz)

        cppHWAddress6 sender_hw_addr() const
        void sender_hw_addr(const cppHWAddress6 &new_snd_hw_addr)

        cppIPv4Address sender_ip_addr() const
        void sender_ip_addr(cppIPv4Address new_snd_ip_addr)

        cppHWAddress6 target_hw_addr() const
        void target_hw_addr(const cppHWAddress6 &new_tgt_hw_addr)

        cppIPv4Address target_ip_addr() const
        void target_ip_addr(cppIPv4Address new_tgt_ip_addr)

        uint16_t hw_addr_format() const
        void hw_addr_format(uint16_t new_hw_addr_fmt)

        uint16_t prot_addr_format() const
        void prot_addr_format(uint16_t new_prot_addr_fmt)

        uint8_t hw_addr_length() const
        void hw_addr_length(uint8_t new_hw_addr_len)

        uint8_t prot_addr_length() const
        void prot_addr_length(uint8_t new_prot_addr_len)

        uint16_t opcode() const
        void opcode(ARP_Flags new_opcode)


    cppEthernetII cpp_make_arp_request "Tins::ARP::make_arp_request" (cppIPv4Address target, cppIPv4Address sender)
    cppEthernetII cpp_make_arp_request "Tins::ARP::make_arp_request" (cppIPv4Address target, cppIPv4Address sender, const cppHWAddress6 &hw_snd)

    cppEthernetII cpp_make_arp_reply "Tins::ARP::make_arp_reply" (cppIPv4Address target, cppIPv4Address sender)
    cppEthernetII cpp_make_arp_reply "Tins::ARP::make_arp_reply" (cppIPv4Address target, cppIPv4Address sender, const cppHWAddress6 &hw_tgt)
    cppEthernetII cpp_make_arp_reply "Tins::ARP::make_arp_reply" (cppIPv4Address target, cppIPv4Address sender, const cppHWAddress6 &hw_tgt, const cppHWAddress6 &hw_snd)


cdef class ARP(PDU):
    cdef cppARP* ptr

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return ARP()
        obj = ARP(_raw=True)
        obj.ptr = new cppARP(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppARP*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj




