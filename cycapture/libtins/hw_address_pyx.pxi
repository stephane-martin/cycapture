# -*- coding: utf-8 -*-

cdef class HWAddress(object):
    """
    Represents the address of a network hardware address
    """
    broadcast = HWAddress("ff:ff:ff:ff:ff:ff")

    def __cinit__(self, object addr=None):
        if addr is None:
            self.ptr = new cppHWAddress6()
        elif isinstance(addr, bytes):
            self.ptr = new cppHWAddress6(<string> (<bytes> addr))
        elif isinstance(addr, HWAddress):
            self.ptr = new cppHWAddress6((<HWAddress> addr).ptr[0])
        else:
            self.ptr = new cppHWAddress6(<string> (bytes(addr)))

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __init__(self, object addr=None):
        """
        __init__(self, object addr=None)

        Parameters
        ----------
        addr: bytes or :py:class:`~.HWAddress`
            make a hardware address from this object
        """

    def __str__(self):
        return bytes(self.ptr.to_string())

    def __repr__(self):
        return "HWAddress('{}')".format(bytes(self.ptr.to_string()))

    cpdef cpp_bool is_broadcast(self):
        """
        Returns
        -------
        bool
            True if the address is a broadcast address.
        """
        return self.ptr.is_broadcast()

    cpdef cpp_bool is_unicast(self):
        """
        Returns
        -------
        bool
            True if the address is a unicast address.
        """
        return self.ptr.is_unicast()

    cpdef cpp_bool is_multicast(self):
        """
        Returns
        -------
        bool
            True if the address is a muticast address.
        """
        return self.ptr.is_multicast()

    def __getitem__(self, item):
        return (self.ptr[0])[int(item)]

    def __richcmp__(self, other, op):
        if isinstance(other, bytes):
            other = HWAddress(other)
        if op == 2:   # equals ==
            return self.equals(other)
        if op == 3:   # different !=
            return self.different(other)
        if not isinstance(other, HWAddress):
            raise ValueError("can't compare HWAddress with %s" % type(other))
        if op == 0:     # less <
            return self.less(other)
        if op == 1:   # <=
            return self.less(other) or self.equals(other)
        if op == 4:   # >
            return not (self.less(other) or self.equals(other))
        if op == 5:   # >=
            return not self.less(other)
        raise ValueError("this comparison is not implemented")

    cpdef equals(self, object other):
        if isinstance(other, bytes):
            other = HWAddress(other)
        if isinstance(other, HWAddress):
            return self.ptr.equals((<HWAddress> other).ptr[0])
        else:
            return False

    cpdef different(self, object other):
        if isinstance(other, bytes):
            other = HWAddress(other)
        if isinstance(other, HWAddress):
            return self.ptr.different((<HWAddress> other).ptr[0])
        else:
            return True

    cpdef less(self, object other):
        if isinstance(other, bytes):
            other = HWAddress(other)
        if isinstance(other, HWAddress):
            return self.ptr.less((<HWAddress> other).ptr[0])
        else:
            raise ValueError("don't know how to compare")

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
        r = HWRange()
        cdef cppHWRange cpp_r = hw_slashrange((<HWAddress>self).ptr[0], <int>int(mask))
        r.clone_from_cpp(cpp_r)
        return r

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
