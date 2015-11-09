# -*- coding: utf-8 -*-

cdef class PacketSender(object):
    """
    Sends packets through a network interface.
    """
    DEFAULT_TIMEOUT = PACKET_SENDER_DEFAULT_TIMEOUT

    SocketType = make_enum('Sender_SocketType', 'SocketType', 'Socket type flags', {
        'ETHER_SOCKET':     PS_ETHER_SOCKET,
        'IP_TCP_SOCKET':    PS_IP_TCP_SOCKET,
        'IP_UDP_SOCKET':    PS_IP_UDP_SOCKET,
        'IP_RAW_SOCKET':    PS_IP_RAW_SOCKET,
        'ARP_SOCKET':       PS_ARP_SOCKET,
        'ICMP_SOCKET':      PS_ICMP_SOCKET,
        'IPV6_SOCKET':      PS_IPV6_SOCKET,
        'SOCKETS_END':      PS_SOCKETS_END
    })

    def __cinit__(self, iface=None, uint32_t recv_timeout=DEFAULT_TIMEOUT, uint32_t usec=0):
        if iface is None:
            self.ptr = new cppPacketSender()
        else:
            if isinstance(iface, IPv4Address):
                iface = NetworkInterface(address=iface)
            if not isinstance(iface, NetworkInterface):
                iface = NetworkInterface(name=iface)
            self.ptr = new cppPacketSender((<NetworkInterface>iface).interface, recv_timeout, usec)

    def __init__(self, iface=None, uint32_t recv_timeout=DEFAULT_TIMEOUT, uint32_t usec=0):
        """
        __init__(iface=None, uint32_t recv_timeout=DEFAULT_TIMEOUT, uint32_t usec=0)

        Parameters
        ----------
        iface: :py:class:`~.NetworkInterface`
            The default interface to use to send the packets
        recv_timeout: `uint32_t`
            The timeout used when receiving responses
        usec: `uint32_t`
            timeout microseconds
        """

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr
            self.ptr = NULL

    property default_interface:
        """
        default interface (read-write, :py:class:`~.NetworkInterface`)
        """
        def __get__(self):
            cdef cppNetworkInterface iface = self.ptr.default_interface()
            return NetworkInterface.factory(&iface)
        def __set__(self, iface):
            if isinstance(iface, IPv4Address):
                iface = NetworkInterface(address=iface)
            if not isinstance(iface, NetworkInterface):
                iface = NetworkInterface(name=iface)
            self.ptr.default_interface((<NetworkInterface>iface).interface)

    cpdef send(self, PDU pdu, iface=None):
        if pdu is None:
            raise ValueError("can't send a None pdu")
        if iface is None:
            self.ptr.send((<PDU> pdu).base_ptr[0])
        else:
            if isinstance(iface, IPv4Address):
                iface = NetworkInterface(address=iface)
            if not isinstance(iface, NetworkInterface):
                iface = NetworkInterface(name=iface)
            self.ptr.send((<PDU> pdu).base_ptr[0], (<NetworkInterface>iface).interface)

    cpdef send_recv(self, PDU pdu, iface=None):
        cdef cppPDU* response = NULL
        cdef PDUType t
        cdef string classname

        if pdu is None:
            raise ValueError("can't send a None pdu")

        if iface is None:
            response = self.ptr.send_recv((<PDU> pdu).base_ptr[0])
        else:
            if isinstance(iface, IPv4Address):
                iface = NetworkInterface(address=iface)
            if not isinstance(iface, NetworkInterface):
                iface = NetworkInterface(name=iface)
            response = self.ptr.send_recv((<PDU> pdu).base_ptr[0], (<NetworkInterface>iface).interface)

        if response is NULL:
            raise RuntimeError("send_recv returned a NULL pointer")
        return PDU.from_ptr(response, parent=None)
