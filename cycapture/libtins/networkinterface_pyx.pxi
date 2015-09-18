# -*- coding: utf-8 -*-

cdef class NetworkInterface(object):
    """
    Represent a network interface
    """
    def __cinit__(self, name=None, address=None):
        if name is None and address is None:
            self.ptr = new cppNetworkInterface()
        elif name is not None:
            name = bytes(name)
            self.ptr = new cppNetworkInterface(<string> name)
        else:
            self._make_from_address(address)

    def __init__(self, name=None, address=None):
        """
        __init__(name=None, address=None)

        Parameters
        ----------
        name: bytes, optional
            if `name` is present (ex: ``'eth0'``), returns this network interface
        address: bytes or :py:class:`~.IPv4Address`, optional
            if `address` is present, returns the interface that would be used to send packets to this address

        Note
        ----
        Give only one parameter, `name` OR `address`.
        """

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    cdef object _make_from_address(self, object address):
        addr = IPv4Address(address)
        self.ptr = new cppNetworkInterface(addr.ptr[0])

    # todo: make property
    cpdef int ident(self):
        """
        Returns
        -------
        int
            interface id
        """
        return int(self.ptr.ident())

    # todo: make property
    cpdef bytes name(self):
        """
        Returns
        -------
        bytes
            interface name
        """
        return <bytes> self.ptr.name()

    # todo: make property
    cpdef object addresses(self):
        """
        Returns
        -------
        dict
            the IPv4 address, netmask, broadcast address and hardware addresss associated with this interface.
        """
        cdef cppNetworkInterface.Info infos = self.ptr.addresses()
        # Info:
        # CPPIPV4Address ip_addr, netmask, bcast_addr
        # HWAddress6 hw_addr
        return {
            'ip_addr': IPv4Address(convert_to_big_endian_int(infos.ip_addr)),
            'netmask': IPv4Address(convert_to_big_endian_int(infos.netmask)),
            'bcast_addr': IPv4Address(convert_to_big_endian_int(infos.bcast_addr)),
            'hw_addr': HWAddress(infos.hw_addr.to_string())
        }

    cpdef cpp_bool is_loopback(self):
        """
        Returns
        -------
        bool
            True if the interface is a loopback interface.
        """
        return self.ptr.is_loopback()

    def __bool__(self):
        return network_interface_to_bool(self.ptr[0])

    @classmethod
    def default(cls):
        """
        Returns
        -------
        default: :py:class:`~.NetworkInterface`
            the default interface.

        Note
        ----
        class method
        """
        cdef cppNetworkInterface default_i = default_interface()
        interface = NetworkInterface(default_i.name())
        return interface

    @classmethod
    def all(cls):
        """
        Returns
        -------
        all: list of :py:class:`~.NetworkInterface`
            a list of all network interfaces

        Note
        ----
        class method
        """
        cdef vector[cppNetworkInterface] all_i = all_interfaces()
        return [NetworkInterface(interface_i.name()) for interface_i in all_i]

    def __str__(self):
        return self.name()

    def __repr__(self):
        return "NetworkInterface('{}')".format(self.name())

