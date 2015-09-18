# -*- coding: utf-8 -*-
"""
PacketSender python class
"""

cdef class PacketSender(object):
    DEFAULT_TIMEOUT = PACKET_SENDER_DEFAULT_TIMEOUT

    ETHER_SOCKET = PS_ETHER_SOCKET
    IP_TCP_SOCKET = PS_IP_TCP_SOCKET
    IP_UDP_SOCKET = PS_IP_UDP_SOCKET
    IP_RAW_SOCKET = PS_IP_RAW_SOCKET
    ARP_SOCKET = PS_ARP_SOCKET
    ICMP_SOCKET = PS_ICMP_SOCKET
    IPV6_SOCKET = PS_IPV6_SOCKET
    SOCKETS_END = PS_SOCKETS_END

    SocketType = Enum('SocketType', {
        'ETHER_SOCKET': ETHER_SOCKET,
        'IP_TCP_SOCKET': IP_TCP_SOCKET,
        'IP_UDP_SOCKET': IP_UDP_SOCKET,
        'IP_RAW_SOCKET': IP_RAW_SOCKET,
        'ARP_SOCKET': ARP_SOCKET,
        'ICMP_SOCKET': ICMP_SOCKET,
        'IPV6_SOCKET': IPV6_SOCKET,
        'SOCKETS_END': SOCKETS_END
    })

    SocketTypeValues = [t.value for t in SocketType]


    def __cinit__(self, iface=None, uint32_t recv_timeout=DEFAULT_TIMEOUT, uint32_t usec=0):
        if iface is None:
            self.ptr = new cppPacketSender()
        else:
            if isinstance(iface, IPv4Address):
                iface = NetworkInterface(address=iface)
            if not isinstance(iface, NetworkInterface):
                iface = NetworkInterface(name=iface)
            self.ptr = new cppPacketSender((<NetworkInterface>iface).ptr[0], recv_timeout, usec)

    def __init__(self, iface=None, uint32_t recv_timeout=DEFAULT_TIMEOUT, uint32_t usec=0):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr
            self.ptr = NULL

    property default_interface:
        def __get__(self):
            cdef cppNetworkInterface iface = self.ptr.default_interface()
            return NetworkInterface.factory(&iface)
        def __set__(self, iface):
            if isinstance(iface, IPv4Address):
                iface = NetworkInterface(address=iface)
            if not isinstance(iface, NetworkInterface):
                iface = NetworkInterface(name=iface)
            self.ptr.default_interface((<NetworkInterface>iface).ptr[0])

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
            self.ptr.send((<PDU> pdu).base_ptr[0], (<NetworkInterface>iface).ptr[0])

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
            response = self.ptr.send_recv((<PDU> pdu).base_ptr[0], (<NetworkInterface>iface).ptr[0])
        if response != NULL:
            # response was allocated with a 'new' inside 'pdu_from_flag': we have responsibility to delete it
            t = response.pdu_type()
            classname = map_pdutype_to_classname[t]
            # make the PDU object and return it
            # last parameter is None, so that the object will be naturally garbage-collected
            return (map_classname_to_factory[classname])(response, NULL, 0, None)
