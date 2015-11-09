# -*- coding: utf-8 -*-
from functools import reduce

# noinspection PyAttributeOutsideInit,PyDocstring
cdef class IPv4Range(object):
    """
    Represents a range of IPv4 addresses.

    To build a range from an address and a mask::

        range = IPv4Address("192.168.0.0") / 16
        range = IPv4Range(first="192.168.0.0", mask="255.255.0.0")
        range = IPv4Range.from_mask("192.168.0.0", 24)

    You can test if an address belongs to a range::

        if address in range:
            print("OK")

    You can also iterate over ranges::

        for i, address in enumerate(range):
            print(i, address)
    """
    def __cinit__(self, first=None, last=None, only_hosts=False, mask=None):
        cdef cppIPv4Range r
        if not isinstance(first, IPv4Address):
            first = IPv4Address(first)
        if mask is None:
            if last is None:
                last = first
            if not isinstance(last, IPv4Address):
                last = IPv4Address(last)
            self.ptr = new cppIPv4Range((<IPv4Address>first).ptr[0], (<IPv4Address>last).ptr[0], only_hosts)
        else:
            if isinstance(mask, IPv4Address):
                r = ipv4_range_from_mask((<IPv4Address>first).ptr[0], (<IPv4Address>mask).ptr[0])
            else:
                try:
                    mask = int(mask)
                    r = ipv4_slashrange((<IPv4Address>first).ptr[0], <int> mask)
                except (ValueError, TypeError):
                    mask = IPv4Address(mask)
                    r = ipv4_range_from_mask((<IPv4Address>first).ptr[0], (<IPv4Address>mask).ptr[0])
            self.ptr = new cppIPv4Range(r)

    def __init__(self, first=None, last=None, only_hosts=False, mask=None):
        """
        __init__(first=None, last=None, only_hosts=False, mask=None)

        Parameters
        ----------
        first: bytes or :py:class:`~.IPv4Address`
            first address in range
        last: bytes or :py:class:`~.IPv4Address`
            last address in range
        only_hosts: bool
            indicates whether only host addresses should be accessed when iterating the range
        mask: bytes or :py:class:`~.IPv4Address`
            range mask

        Note
        ----
        Provide `last` *OR* `mask`
        """

    def __dealloc__(self):
        if self.ptr is not NULL:
            del self.ptr
        self.ptr = NULL

    def __contains__(self, addr):
        if not isinstance(addr, IPv4Address):
            addr = IPv4Address(addr)
        return bool(self.ptr.contains((<IPv4Address>addr).ptr[0]))

    cpdef is_iterable(self):
        """
        is_iterable()

        Returns
        -------
        bool
            True if the range is iterable.
        """
        return bool(self.ptr.is_iterable())

    def size(self):
        """
        size()

        Returns
        -------
        int
            the range's size (how many addresses in the range)
        """
        if not self.is_iterable():
            raise TypeError("not iterable")
        first = str(self.first).split('.')
        last = str(self.last).split('.')
        diff = map(lambda x, y: x - y, last, first)
        return reduce(lambda x, y: 256 * x + y, diff)

    @classmethod
    def from_mask(cls, address, mask):
        """
        from_mask(address, mask)
        Construct a range from an address and a mask.

        Parameters
        ----------
        address: bytes or :py:class:`~.IPv4Address`
            address (ex: `192.168.1.0`)
        mask: bytes or :py:class:`~.IPv4Address`
            mask (ex: `255.255.255.0`)

        Returns
        -------
        range: :py:class:`~.IPv4Range`
            new IPv4 range

        Note
        ====
        class method
        """
        return IPv4Range(address, mask=mask)

    cdef clone_from_cpp(self, cppIPv4Range r):
        del self.ptr
        self.ptr = new cppIPv4Range(r)

    property first:
        """
        The first address in range (read-only property)
        """
        def __get__(self):
            return IPv4Address(<bytes>(self.ptr.begin().ref().to_string()))

    property last:
        """
        The last address in range (read-only property)
        """
        def __get__(self):
            return IPv4Address(<bytes>(self.ptr.end().ref().to_string()))

    def __iter__(self):
        if not self.is_iterable():
            raise TypeError("The range is not iterable")
        cdef ipv4_range_iterator* it = <ipv4_range_iterator*> PyMem_Malloc(sizeof(ipv4_range_iterator))
        if it is NULL:
            raise MemoryError()
        try:
            it[0] = self.ptr.begin()
            while it[0] != self.ptr.end():
                yield IPv4Address(it[0].ref().to_string())
                inc(it[0])
        finally:
            PyMem_Free(it)

    def __str__(self):
        return b"{} -> {}".format(str(self.first), str(self.last))

    def __repr__(self):
        return b"IPv4Range(first='{}', last='{}')".format(str(self.first), str(self.last))

    def __hash__(self):
        return hash((self.first, self.last))


# noinspection PyDocstring,PyAttributeOutsideInit
cdef class IPv6Range(object):
    """
    Represents a range of IPv6 addresses.

    You can test if an address belongs to a range::

        if address in range:
            print("OK")

    You can also iterate over ranges::

        for i, address in enumerate(range):
            print(i, address)
    """
    def __cinit__(self, first=None, last=None, only_hosts=False, mask=None):
        cdef cppIPv6Range r
        if not isinstance(first, IPv6Address):
            first = IPv6Address(first)
        if mask is None:
            if last is None:
                last = first
            if not isinstance(last, IPv6Address):
                last = IPv6Address(last)
            self.ptr = new cppIPv6Range((<IPv6Address>first).ptr[0], (<IPv6Address>last).ptr[0], only_hosts)
        else:
            if isinstance(mask, IPv6Address):
                r = ipv6_range_from_mask((<IPv6Address>first).ptr[0], (<IPv6Address>mask).ptr[0])
            else:
                try:
                    mask = int(mask)
                    r = ipv6_slashrange((<IPv6Address>first).ptr[0], <int> mask)
                except (ValueError, TypeError):
                    mask = IPv6Address(mask)
                    r = ipv6_range_from_mask((<IPv6Address>first).ptr[0], (<IPv6Address>mask).ptr[0])
            self.ptr = new cppIPv6Range(r)

    def __init__(self, first=None, last=None, only_hosts=False, mask=None):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __contains__(self, addr):
        if not isinstance(addr, IPv6Address):
            addr = IPv6Address(addr)
        return bool(self.ptr.contains((<IPv6Address>addr).ptr[0]))

    cpdef is_iterable(self):
        """
        is_iterable()
        Returns
        -------
        bool
            True if the range is iterable.
        """
        return bool(self.ptr.is_iterable())

    def size(self):
        """
        size()
        Returns
        -------
        int
            the range's size (how many addresses in the range)
        """
        if not self.is_iterable():
            raise TypeError("not iterable")
        first = self.first.full_repr()
        last = self.last.full_repr()
        diff = map(lambda x, y: x - y, last, first)
        return reduce(lambda x, y: 256 * x + y, diff)


    @classmethod
    def from_mask(cls, address, mask):
        """
        Construct an IPv6Range from an address and a mask

        Parameters
        ----------
        first: bytes or :py:class:`~.IPv6Address`
            base IPv6 address
        mask: bytes or :py:class:`~.IPv6Address`
            IPv6 mask

        Returns
        -------
        range: :py:class:`~.IPv6Range`
            new IPv6 range
        """
        return IPv6Range(address, mask=mask)

    cdef clone_from_cpp(self, cppIPv6Range r):
        del self.ptr
        self.ptr = new cppIPv6Range(r)

    property first:
        """
        First adddress in range (read-only property)
        """
        def __get__(self):
            return IPv6Address(<bytes>(self.ptr.begin().ref().to_string()))

    property last:
        """
        Last address in range (read-only propperty)
        """
        def __get__(self):
            return IPv6Address(<bytes>(self.ptr.end().ref().to_string()))

    def __iter__(self):
        if not self.is_iterable():
            raise TypeError("The range is not iterable")
        cdef ipv6_range_iterator* it = <ipv6_range_iterator*> PyMem_Malloc(sizeof(ipv6_range_iterator))
        if it is NULL:
            raise MemoryError()
        try:
            it[0] = self.ptr.begin()
            while it[0] != self.ptr.end():
                yield IPv6Address(it[0].ref().to_string())
                inc(it[0])
        finally:
            PyMem_Free(it)

    def __str__(self):
        return b"{} -> {}".format(str(self.first), str(self.last))

    def __repr__(self):
        return b"IPv4Range(first='{}', last='{}')".format(str(self.first), str(self.last))

    def __hash__(self):
        return hash((self.first, self.last))


cdef class HWRange(object):
    """
    Represents a range of hardware addresses.

    You can test if an address belongs to a range::

        if address in range:
            print("OK")

    You can also iterate over ranges::

        for i, address in enumerate(range):
            print(i, address)
    """
    def __cinit__(self, first=None, last=None, only_hosts=False, mask=None):
        cdef cppHWRange r
        if not isinstance(first, HWAddress):
            first = HWAddress(first)
        if mask is None:
            if last is None:
                last = first
            if not isinstance(last, HWAddress):
                last = HWAddress(bytes(last))
            self.ptr = new cppHWRange((<HWAddress>first).ptr[0], (<HWAddress>last).ptr[0], only_hosts)
        else:
            if isinstance(mask, HWAddress):
                r = hw_range_from_mask((<HWAddress>first).ptr[0], (<HWAddress>mask).ptr[0])
            else:
                try:
                    mask = int(mask)
                    r = hw_slashrange((<HWAddress>first).ptr[0], <int> mask)
                except (ValueError, TypeError):
                    mask = HWAddress(mask)
                    r = hw_range_from_mask((<HWAddress>first).ptr[0], (<HWAddress>mask).ptr[0])
            self.ptr = new cppHWRange(r)

    def __init__(self, first=None, last=None, only_hosts=False, mask=None):
        pass

    def __dealloc__(self):
        if self.ptr is not NULL:
            del self.ptr
        self.ptr = NULL

    def __contains__(self, addr):
        if not isinstance(addr, HWAddress):
            addr = HWAddress(addr)
        return bool(self.ptr.contains((<HWAddress>addr).ptr[0]))

    cpdef is_iterable(self):
        """
        is_iterable()
        Returns
        -------
        bool
            True if the range is iterable.
        """
        return bool(self.ptr.is_iterable())

    @classmethod
    def from_mask(cls, address, mask):
        """
        Construct a HWRange from an address and a mask

        Parameters
        ----------
        address: bytes or :py:class:`~.HWAddress`
            base hardware address
        mask: bytes or :py:class:`~.HWAddress`
            range mask

        Returns
        -------
        range: :py:class:`~.HWRange`
            new harware range
        """
        return HWRange(address, mask=mask)

    cdef clone_from_cpp(self, cppHWRange r):
        del self.ptr
        self.ptr = new cppHWRange(r)

    property first:
        """
        First address in range (read-only property)
        """
        def __get__(self):
            return HWAddress(<bytes>(self.ptr.begin().ref().to_string()))

    property last:
        """
        Last address in range (read-only property)
        """
        def __get__(self):
            return HWAddress(<bytes>(self.ptr.end().ref().to_string()))

    def __iter__(self):
        if not self.is_iterable():
            raise TypeError("The range is not iterable")
        cdef hw_range_iterator* it = <hw_range_iterator*> PyMem_Malloc(sizeof(hw_range_iterator))
        if it is NULL:
            raise MemoryError()
        try:
            it[0] = self.ptr.begin()
            while it[0] != self.ptr.end():
                yield HWAddress(it[0].ref().to_string())
                inc(it[0])
        finally:
            PyMem_Free(it)

    def size(self):
        """
        size()
        Returns
        -------
        int
            the range's size (how many addresses in the range)
        """
        if not self.is_iterable():
            raise TypeError("not iterable")
        first = self.first.full_repr()
        last = self.last.full_repr()
        diff = map(lambda x, y: x - y, last, first)
        return reduce(lambda x, y: 256 * x + y, diff)

    def __str__(self):
        return b"{} -> {}".format(str(self.first), str(self.last))

    def __repr__(self):
        return b"IPv4Range(first='{}', last='{}')".format(str(self.first), str(self.last))

    def __hash__(self):
        return hash((self.first, self.last))
