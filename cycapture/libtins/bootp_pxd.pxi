# -*- coding: utf-8 -*-

cdef extern from "tins/bootp.h" namespace "Tins" nogil:
    PDUType bootp_pdu_flag "Tins::BootP::pdu_flag"

    enum BootP_OpCodes "Tins::BootP::OpCodes":
        BOOTP_BOOTREQUEST "Tins::BootP::BOOTREQUEST",
        BOOTP_BOOTREPLY "Tins::BootP::BOOTREPLY"

    cppclass cppBootP "Tins::BootP" (cppPDU):
        cppBootP()
        cppBootP(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        uint8_t opcode() const
        void opcode(uint8_t new_opcode)

        uint8_t htype() const
        void htype(uint8_t new_htype)

        uint8_t hlen() const
        void hlen(uint8_t new_hlen)

        uint8_t hops() const
        void hops(uint8_t new_hops)

        uint32_t xid() const
        void xid(uint32_t new_xid)

        uint16_t secs() const
        void secs(uint16_t new_secs)

        uint16_t padding() const
        void padding(uint16_t new_padding)

        cppIPv4Address ciaddr() const
        void ciaddr(cppIPv4Address new_ciaddr)

        cppIPv4Address yiaddr() const
        void yiaddr(cppIPv4Address new_yiaddr)

        cppIPv4Address siaddr() const
        void siaddr(cppIPv4Address new_siaddr)

        cppIPv4Address giaddr() const
        void giaddr(cppIPv4Address new_giaddr)

        cppHWAddress16 chaddr() const
        # template<size_t n> void chaddr(const HWAddress<n> &new_chaddr)

        const uint8_t *sname() const
        void sname(const uint8_t *new_sname)

        const uint8_t *file() const
        void file(const uint8_t *new_file)

        const vector[uint8_t] &vend() const
        void vend(const vector[uint8_t] &new_vend)

cdef extern from "wrap.h" namespace "Tins" nogil:
    void bootp_set_chaddr(cppBootP& bootp_obj, const cppHWAddress16 &new_chaddr)

cdef class BootP(PDU):
    cdef cppBootP* ptr

