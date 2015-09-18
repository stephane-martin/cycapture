# -*- coding: utf-8 -*-

cdef extern from "tins/packet_sender.h" namespace "Tins" nogil:

    cdef uint32_t PACKET_SENDER_DEFAULT_TIMEOUT "Tins::PacketSender::DEFAULT_TIMEOUT"
    cdef enum PS_SocketType "Tins::PacketSender::SocketType":
        PS_ETHER_SOCKET "Tins::PacketSender::ETHER_SOCKET",
        PS_IP_TCP_SOCKET "Tins::PacketSender::IP_TCP_SOCKET",
        PS_IP_UDP_SOCKET "Tins::PacketSender::IP_UDP_SOCKET",
        PS_IP_RAW_SOCKET "Tins::PacketSender::IP_RAW_SOCKET",
        PS_ARP_SOCKET "Tins::PacketSender::ARP_SOCKET",
        PS_ICMP_SOCKET "Tins::PacketSender::ICMP_SOCKET",
        PS_IPV6_SOCKET "Tins::PacketSender::IPV6_SOCKET",
        PS_SOCKETS_END "Tins::PacketSender::SOCKETS_END"

    cdef cppclass cppPacketSender "Tins::PacketSender":
        cppPacketSender()
        cppPacketSender(const cppNetworkInterface &iface) except +custom_exception_handler
        cppPacketSender(const cppNetworkInterface &iface, uint32_t recv_timeout) except +custom_exception_handler
        cppPacketSender(const cppNetworkInterface &iface, uint32_t recv_timeout, uint32_t usec) except +custom_exception_handler
        void open_l3_socket(PS_SocketType t) except +custom_exception_handler
        void close_socket(PS_SocketType t) except +custom_exception_handler
        void close_socket(PS_SocketType t, const cppNetworkInterface &iface) except +custom_exception_handler
        const cppNetworkInterface& default_interface() const
        void default_interface(const cppNetworkInterface &iface)
        void send(cppPDU &pdu) except +custom_exception_handler
        void send(cppPDU &pdu, const cppNetworkInterface &iface) except +custom_exception_handler
        cppPDU *send_recv(cppPDU &pdu) except +custom_exception_handler
        cppPDU *send_recv(cppPDU &pdu, const cppNetworkInterface &iface) except +custom_exception_handler


cdef class PacketSender(object):
    cdef cppPacketSender* ptr
    cpdef send(self, PDU pdu, iface=?)
    cpdef send_recv(self, PDU pdu, iface=?)
