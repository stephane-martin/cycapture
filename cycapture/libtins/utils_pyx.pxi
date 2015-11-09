# -*- coding: utf-8 -*-

cdef class RouteEntry(object):
    """
    Encapsulate a route entry.

    RouteEntry supports equality testing, copying, reducing, and hashing.
    """
    def __init__(self, interface, destination, gateway, mask):
        """
        __init__(interface, destination, gateway, mask)

        Parameters
        ----------
        interface: bytes
        destination: IPv4Address
        gateway: IPv4Address
        mask: IPv4Address
        """
        self.interface = bytes(interface)
        self.destination = IPv4Address(destination)
        self.gateway = IPv4Address(gateway)
        self.mask = IPv4Address(mask)

    def __str__(self):
        return b"Interface: {}    Destination: {}    Gateway: {}    Mask: {}".format(
            self.interface, str(self.destination), str(self.gateway), str(self.mask)
        )

    def __repr__(self):
        return b"RouteEntry('{}', '{}', '{}', '{}')".format(
            self.interface, str(self.destination), str(self.gateway), str(self.mask)
        )

    def __copy__(self):
        return RouteEntry(
            bytes(self.interface),
            self.destination.__copy__(),
            self.gateway.__copy__(),
            self.mask.__copy__()
        )

    def __reduce__(self):
        return RouteEntry, (self.interface, self.destination, self.gateway, self.mask)

    @staticmethod
    cdef from_cpp(cppRouteEntry r):
        return RouteEntry(
            <bytes> r.interface,
            <bytes> r.destination.to_string(),
            <bytes> r.gateway.to_string(),
            <bytes> r.mask.to_string()
        )

    def __hash__(self):
        return hash((self.interface, str(self.destination), str(self.gateway), str(self.mask)))

    cdef equals(self, other):
        if not isinstance(other, RouteEntry):
            return False
        return self.interface == (<RouteEntry> other).interface \
               and self.destination == (<RouteEntry> other).destination \
               and self.gateway == (<RouteEntry> other).gateway \
               and self.mask == (<RouteEntry> other).mask

    def __richcmp__(self, other, op):
        if op == 2:
            return (<RouteEntry> self).equals(other)
        if op == 3:
            return not (<RouteEntry> self).equals(other)
        raise ValueError("unsupported operation")

cdef class Utils(object):
    """
    Various utilities provided by libtins.
    """

    @staticmethod
    def list_route_entries():
        """
        list_route_entries()
        List the system route entries.

        Returns
        -------
        routes: list of :py:class:`~.RouteEntry`
        """
        cdef vector[cppRouteEntry] v = route_entries()
        return [RouteEntry.from_cpp(r) for r in v]

    @staticmethod
    def list_network_interfaces():
        """
        list_network_interfaces()
        Returns the list of available network interfaces.

        Returns
        -------
        interfaces: list of :py:class:`~.NetworkInterface`
        """
        s = <set> cpp_network_interfaces()
        return [NetworkInterface(i) for i in s]

    @staticmethod
    def pdutype_to_string(int t):
        """
        pdutype_to_string(int t)

        Parameters
        ----------
        t: int
            the pdu type as an integer

        Returns
        -------
        the pdu type as a string
        """
        return <bytes> cpp_pdutype_to_string(<PDUType> t)

    @staticmethod
    def ip_to_gateway(ip):
        """
        ip_to_gateway(ip)
        Returns the gateway that will be used for the given IP address

        Parameters
        ----------
        ip: bytes or :py:class:`~.IPv4Address`

        Returns
        -------
        gateway: :py:class:`~.IPv4Address`
        """
        ip = IPv4Address(ip)
        cdef cppIPv4Address gw
        if not gateway_from_ip((<IPv4Address> ip).ptr[0], gw):
            raise RuntimeError("gateway lookup failed")
        return IPv4Address(gw.to_string())

    @staticmethod
    def resolve_domain(domain):
        """
        resolve_domain(domain)
        Resolve the given domain to IPv4 address

        Parameters
        ----------
        domain: bytes

        Returns
        -------
        address: :py:class:`~.IPv4Address`
        """
        domain = bytes(domain)
        return IPv4Address(cpp_resolve_domain(<string> domain).to_string())

    @staticmethod
    def resolve_domain6(domain):
        """
        resolve_domain6(domain)
        Resolve the given domain to IPv6 address

        Parameters
        ----------
        domain: bytes

        Returns
        -------
        address: :py:class:`~.IPv6Address`
        """
        domain = bytes(domain)
        return IPv6Address(cpp_resolve_domain6(<string> domain).to_string())

    @staticmethod
    def channel_to_mhz(channel):
        """
        channel_to_mhz(channel)
        Convert a channel to frequence

        Parameters
        ----------
        channel: uint16_t

        Returns
        -------
        frequence: uint16_t
        """
        return int(cpp_channel_to_mhz(<uint16_t> int(channel)))

    @staticmethod
    def mhz_to_channel(mhz):
        """
        mhz_to_channel(mhz)
        Convert a frequence to channel

        Parameters
        ----------
        mhz: uint16_t

        Returns
        -------
        channel: uint16_t
        """
        return int(cpp_mhz_to_channel(<uint16_t> int(mhz)))

