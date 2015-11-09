# -*- coding: utf-8 -*-

cdef class HWAddress(object):
    """
    Represents the address of a network hardware address
    """
    broadcast = HWAddress("ff:ff:ff:ff:ff:ff")

    def __cinit__(self, addr=None):
        if addr is None:
            self.ptr = new cppHWAddress6()
        elif isinstance(addr, unicode):
            self.ptr = new cppHWAddress6(<string> (<bytes> (addr.encode('ascii'))))
        elif isinstance(addr, bytes):
            self.ptr = new cppHWAddress6(<string> (<bytes> addr))
        elif isinstance(addr, HWAddress):
            self.ptr = new cppHWAddress6((<HWAddress> addr).ptr[0])
        else:
            self.ptr = new cppHWAddress6(<string> (bytes(addr)))

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __init__(self, addr=None):
        """
        __init__(self, object addr=None)

        Parameters
        ----------
        addr: bytes or :py:class:`~.HWAddress`
            make a hardware address from this object
        """

    def __hash__(self):
        return hash(str(self))

    def __str__(self):
        return bytes(self.ptr.to_string())

    def __repr__(self):
        return "HWAddress('{}')".format(bytes(self.ptr.to_string()))

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
            True if the address is a muticast address.
        """
        return bool(self.ptr.is_multicast())

    def __getitem__(self, item):
        return int((self.ptr[0])[int(item)])

    def __richcmp__(self, other, op):
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
        if not isinstance(other, HWAddress):
            try:
                other = HWAddress(other)
            except ValueError:
                return False
        return self.ptr.equals((<HWAddress> other).ptr[0])

    cpdef different(self, other):
        if not isinstance(other, HWAddress):
            try:
                other = HWAddress(other)
            except ValueError:
                return True
        return self.ptr.different((<HWAddress> other).ptr[0])

    cpdef less(self, other):
        if not isinstance(other, HWAddress):
            other = HWAddress(other)
        return self.ptr.less((<HWAddress> other).ptr[0])

    def __div__(self, mask):
        """
        x/y represents the hardware address range corresponding to base address x with mask y.

        Parameters
        ----------
        mask: int
            the mask as an integer

        Returns
        -------
        range: :py:class:`~.HWRange`
            new hardware ranges
        """
        if not isinstance(self, HWAddress):
            raise TypeError("operation not supported")
        return HWRange(first=self, mask=mask)

    def __truediv__(self, mask):
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
        return HWAddress(str(self))

    def __reduce__(self):
        return HWAddress, (str(self), )

    cpdef to_bytes(self):
        return <bytes> (self.ptr.begin()[:6])
