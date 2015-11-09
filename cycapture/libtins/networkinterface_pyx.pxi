# -*- coding: utf-8 -*-

cdef class NetworkInterface(object):
    """
    Represent a network interface

    NetworkInterface objects support equality::

        if not NetworkInterface() != NetworkInterface.default():
            print('boo')

    NetworkInterface objects can be hashed::

        print(hash(NetworkInterface.default()))
    """

    NI_addresses_tuple = namedtuple('NI_addresses_tuple', [
        "address", "netmask", "broadcast", "hardware"
    ])

    def __cinit__(self, name=None, address=None):
        if name is None and address is None:
            self.interface = cppNetworkInterface()
        elif name is not None:
            name = bytes(name)
            try:
                self.interface = cppNetworkInterface(<string> name)
            except RuntimeError as ex:
                if "invalid interface" in ex.args[0].lower():
                    raise InvalidInterface
                raise
        else:
            if not isinstance(address, IPv4Address):
                address = IPv4Address(address)
            try:
                self.interface = cppNetworkInterface((<IPv4Address> address).ptr[0])
            except RuntimeError as ex:
                if "invalid interface" in ex.args[0].lower():
                    raise InvalidInterface
                raise

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

    cpdef equals(self, other):
        """
        equals(other)

        Parameters
        ----------
        other: object
            any python object

        Returns
        -------
        bool
            Returns True if self equals other
        """
        if not isinstance(other, NetworkInterface):
            try:
                other = NetworkInterface(other)
            except (ValueError, TypeError):
                return False
        return self.interface == (<NetworkInterface> other).interface

    def __richcmp__(self, other, op):
        if op == 2:   # equals ==
            return (<NetworkInterface> self).equals(other)
        if op == 3:   # different !=
            return not (<NetworkInterface> self).equals(other)
        raise ValueError("this comparison is not implemented")

    def __hash__(self):
        return hash((self.id, self.name))

    property id:
        """
        Returns the interface id (read-only property)
        """
        def __get__(self):
            return int(self.interface.ident())

    property name:
        """
        Returns the interface name (read-only property)
        """
        def __get__(self):
            return <bytes>(self.interface.name())

    property addresses:
        """
        the IPv4 address, netmask, broadcast address and hardware addresss associated with this interface.
        """
        def __get__(self):
            cdef cppNetworkInterface.Info infos = self.interface.addresses()
            return NetworkInterface.NI_addresses_tuple(
                IPv4Address(infos.ip_addr.to_uint32()),
                IPv4Address(infos.netmask.to_uint32()),
                IPv4Address(infos.bcast_addr.to_uint32()),
                HWAddress(infos.hw_addr.to_string())
            )

    cpdef is_loopback(self):
        """
        is_loopback()

        Returns
        -------
        bool
            True if the interface is a loopback interface.
        """
        return bool(self.interface.is_loopback())

    def __bool__(self):
        return bool(self.interface.to_bool())

    @classmethod
    def default(cls):
        """
        default()

        Returns
        -------
        default: :py:class:`~.NetworkInterface`
            the default interface.

        Note
        ----
        class method
        """
        return NetworkInterface(default_interface().name())

    @classmethod
    def all(cls):
        """
        all()

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
        return self.name

    def __repr__(self):
        return b"NetworkInterface('{}')".format(self.name)

    def __copy__(self):
        return NetworkInterface(str(self))

    def __reduce__(self):
        return NetworkInterface, (str(self), )
