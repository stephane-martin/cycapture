# encoding: utf-8

cdef class IPv4Address(object):
    """
    Encapsulate an IPv4 address.

    IPv4Address implements rich comparison::

        IPv4Address("192.168.0.1") != IPv4Address("8.8.8.8")
        IPv4Address("192.168.0.1") > IPv4Address("8.8.8.8")

    IPv4Address can be hashed::

        print(hash(IPv4Address("192.168.0.1")))

    To get the integer representation::

        print(int(IPv4Address("192.168.0.1")))

    IPv4 ranges can be be built from addresses::

        range = IPv4Address("192.168.0.1") / 24
    """
    broadcast = IPv4Address("255.255.255.255")

    def __cinit__(self, addr=None):
        if addr is None:
            self.ptr = new cppIPv4Address()
        elif isinstance(addr, int):
            self.ptr = new cppIPv4Address(<uint32_t> addr)
        elif isinstance(addr, unicode):
            addr = addr.encode('ascii')
            self.ptr = new cppIPv4Address(<string> (<bytes> addr))
        elif isinstance(addr, bytes):
            self.ptr = new cppIPv4Address(<string> (<bytes> addr))
        elif isinstance(addr, IPv4Address):
            self.ptr = new cppIPv4Address((<IPv4Address> addr).ptr.to_uint32())
        else:
            addr = bytes(addr)
            self.ptr = new cppIPv4Address(<string> addr)

    def __init__(self, addr=None):
        """
        __init__(self, addr=None)

        Parameters
        ----------
        addr: int or bytes or :py:class:`~.IPv4Address`
            make an IPv4 address from this object
        """

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __str__(self):
        return <bytes> (self.ptr.to_string())

    def __repr__(self):
        return b"IPv4Address('{}')".format(<bytes> (self.ptr.to_string()))

    cpdef is_loopback(self):
        """
        Returns
        -------
        bool
            True if the address is a loopback address.
        """
        return bool(self.ptr.is_loopback())

    cpdef is_private(self):
        """
        Returns
        -------
        bool
            True if the address is a private address.
        """
        return bool(self.ptr.is_private())

    cpdef is_broadcast(self):
        """
        Returns
        -------
        bool
            True if the address is a broadcast address.
        """
        return bool(self.ptr.is_broadcast())

    cpdef is_unicast(self):
        """
        Returns
        -------
        bool
            True if the address is a unicast address.
        """

        return bool(self.ptr.is_unicast())

    cpdef is_multicast(self):
        """
        Returns
        -------
        bool
            True if the address is a multicast address.
        """

        return bool(self.ptr.is_multicast())

    def __richcmp__(self, other, op):
        if not isinstance(other, IPv4Address):
            other = IPv4Address(other)
        if op == 2:   # equals ==
            return self.equals(other)
        if op == 3:   # different !=
            return self.different(other)
        if op == 0:     # less <
            return self.less(other)
        if op == 1:   # <=
            return self.less(other) or self.equals(other)
        if op == 4:   # >
            return not (self.less(other) or self.equals(other))
        if op == 5:   # >=
            return not self.less(other)
        raise ValueError("this comparison is not implemented")

    cpdef equals(self, other):
        if not isinstance(other, IPv4Address):
            try:
                other = IPv4Address(other)
            except ValueError:
                return False
        return self.ptr.equals((<IPv4Address> other).ptr[0])

    cpdef different(self, other):
        if not isinstance(other, IPv4Address):
            try:
                other = IPv4Address(other)
            except ValueError:
                return True
        return self.ptr.different((<IPv4Address> other).ptr[0])

    cpdef less(self, other):
        if not isinstance(other, IPv4Address):
            other = IPv4Address(other)
        return self.ptr.less((<IPv4Address> other).ptr[0])

    def __int__(self):
        """
        __int__(self)
        Convert the address to its integer representation.

        Returns
        -------
        int
            integer representation
        """
        return int(self.ptr.to_uint32())

    def __hash__(self):
        return hash(int(self))

    def __div__(self, mask):
        """
        __div__(self, mask)
        ``x/y`` represents the IPv4 range corresponding to base address x with mask y.

        Parameters
        ----------
        mask: int
            the mask as an integer or as an IPv4Address

        Returns
        -------
        range: :py:class:`~.IPv4Range`
            new IPv4 range
        """
        return IPv4Range(first=self, mask=mask)

    def __truediv__(self, mask):
        return self.__div__(mask)

    def __copy__(self):
        return IPv4Address(int(self))

    def __reduce__(self):
        return IPv4Address, (str(self),)
