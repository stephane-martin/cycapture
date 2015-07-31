# -*- coding: utf-8 -*-

cdef extern from "tins/ethernetII.h" namespace "Tins":
    # noinspection PyUnresolvedReferences
    PDUType ethII_pdu_flag "Tins::EthernetII::pdu_flag"
    cppHWAddress6 ethII_BROADCAST "Tins::EthernetII::BROADCAST"

    cdef cppclass EthernetII:
        EthernetII()
        EthernetII(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        EthernetII(const unsigned char *buf, unsigned int total_sz)
        cppHWAddress6 dst_addr() const
        cppHWAddress6 src_addr() const
        unsigned short payload_type()
        void dst_addr(const cppHWAddress6 &new_dst_addr)
        void src_addr(const cppHWAddress6 &new_src_addr)
        void payload_type(unsigned short new_payload_type)
        unsigned int header_size() const
        unsigned int trailer_size() const
        # noinspection PyUnresolvedReferences
        PDUType pdu_type() const
        EthernetII *clone() const
        # noinspection PyUnresolvedReferences
        pointer find_pdu[T]()
