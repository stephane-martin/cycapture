# -*- coding: utf-8 -*-

cdef class IPv6Address(object):
    """
    Encapsulate an IPv6 address.
    """

    def __cinit__(self, addr=None):
        if addr is None:
            self.ptr = new cppIPv6Address()
        elif isinstance(addr, unicode):
            addr = addr.encode('ascii')
            self.ptr = new cppIPv6Address(<string> (<bytes> addr))
        elif isinstance(addr, bytes):
            self.ptr = new cppIPv6Address(<string> (<bytes> addr))
        elif isinstance(addr, IPv6Address):
            self.ptr = new cppIPv6Address(<string> str(addr))
        else:
            self.ptr = new cppIPv6Address(<string> (bytes(addr)))

    cpdef to_buffer(self):
        return <bytes> (self.ptr.begin()[:16])

    def __init__(self, object addr=None):
        """
        __init__(self, object addr=None)

        Parameters
        ----------
        addr: bytes or :py:class:`~.IPv6Address`
            make an IPv6 address from this object
        """

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __str__(self):
        return bytes(self.ptr.to_string()).decode('utf-8')

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return "IPv6Address('{}')".format(bytes(self.ptr.to_string()))

    cpdef is_loopback(self):
        """
        Returns
        -------
        bool
            True if the address is a loopback address.
        """
        return bool(self.ptr.is_loopback())

    cpdef is_multicast(self):
        """
        Returns
        -------
        bool
            True if the address is a multicast address.
        """
        return bool(self.ptr.is_multicast())

    def __richcmp__(self, other, op):
        if not isinstance(other, IPv6Address):
            other = IPv6Address(other)
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
        if not isinstance(other, IPv6Address):
            try:
                other = IPv6Address(other)
            except (TypeError, ValueError):
                return False
        return self.ptr[0] == (<IPv6Address> other).ptr[0]

    cpdef different(self, other):
        if isinstance(other, IPv6Address):
            try:
                other = IPv6Address(other)
            except ValueError:
                return True
        return self.ptr[0] != (<IPv6Address> other).ptr[0]

    cpdef less(self, object other):
        if isinstance(other, IPv6Address):
            other = IPv6Address(other)
        return self.ptr[0] < (<IPv6Address> other).ptr[0]

    def __div__(self, mask):
        """
        x/y represents the IPv6 range corresponding to base address x with mask y.

        Parameters
        ----------
        mask: int
            the mask as an integer

        Returns
        -------
        range: :py:class:`~.IPv6Range`
            new IPv6 range
        """
        if not isinstance(self, IPv6Address):
            raise TypeError("operation not supported")
        return IPv6Range(first=self, mask=mask)

    def __itruediv__(self, mask):
        return self.__div__(mask)

    cpdef full_repr(self):
        """
        Returns
        -------
        list of int
            the 6 bytes composing the address as a list of integers.
        """
        cdef vector[uint8_t] v
        v.assign(self.ptr.begin(), self.ptr.end())
        return <list> v

    def __copy__(self):
        return IPv6Address(str(self))

    def __reduce__(self):
        return IPv6Address, (str(self), )
