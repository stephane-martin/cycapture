# -*- coding: utf-8 -*-


from functools import reduce

cdef class IPv4Range(object):
    def __cinit__(self, first=None, last=None, only_hosts=False, mask=None):
        cdef cppIPv4Range r
        if first is None:
            first = IPv4Address()
        if not isinstance(first, IPv4Address):
            first = IPv4Address(bytes(first))
        if mask is None:
            if last is None:
                last = first
            if not isinstance(last, IPv4Address):
                last = IPv4Address(bytes(last))
            self.ptr = new cppIPv4Range((<IPv4Address>first).ptr[0], (<IPv4Address>last).ptr[0], only_hosts)
        else:
            if not isinstance(mask, IPv4Address):
                mask = IPv4Address(bytes(mask))
            r = ipv4_range_from_mask((<IPv4Address>first).ptr[0], (<IPv4Address>mask).ptr[0])
            self.ptr = new cppIPv4Range(r)

    def __init__(self, first=None, last=None, only_hosts=False, mask=None):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __contains__(self, addr):
        if not isinstance(addr, IPv4Address):
            addr = IPv4Address(bytes(addr))
        return bool(self.ptr.contains((<IPv4Address>addr).ptr[0]))

    cpdef is_iterable(self):
        return bool(self.ptr.is_iterable())

    def size(self):
        if not self.is_iterable():
            raise TypeError("not iterable")
        first = str(self.first).split('.')
        last = str(self.last).split('.')
        diff = map(lambda x, y: x - y, last, first)
        return reduce(lambda x, y: 256 * x + y, diff)

    @classmethod
    def from_mask(cls, first, mask):
        return IPv4Range(first, mask=mask)

    cdef clone_from_cpp(self, cppIPv4Range r):
        del self.ptr
        self.ptr = new cppIPv4Range(r)

    property first:
        def __get__(self):
            return IPv4Address(<bytes>(self.ptr.begin().ref().to_string()))

    property last:
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


cdef class IPv6Range(object):
    def __cinit__(self, first=None, last=None, only_hosts=False, mask=None):
        cdef cppIPv6Range r
        if first is None:
            first = IPv6Address()
        if not isinstance(first, IPv6Address):
            first = IPv6Address(bytes(first))
        if mask is None:
            if last is None:
                last = first
            if not isinstance(last, IPv6Address):
                last = IPv6Address(bytes(last))
            self.ptr = new cppIPv6Range((<IPv6Address>first).ptr[0], (<IPv6Address>last).ptr[0], only_hosts)
        else:
            if not isinstance(mask, IPv6Address):
                mask = IPv6Address(bytes(mask))
            r = ipv6_range_from_mask((<IPv6Address>first).ptr[0], (<IPv6Address>mask).ptr[0])
            self.ptr = new cppIPv6Range(r)

    def __init__(self, first=None, last=None, only_hosts=False, mask=None):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __contains__(self, addr):
        if not isinstance(addr, IPv6Address):
            addr = IPv6Address(bytes(addr))
        return bool(self.ptr.contains((<IPv6Address>addr).ptr[0]))

    cpdef is_iterable(self):
        return bool(self.ptr.is_iterable())

    def size(self):
        if not self.is_iterable():
            raise TypeError("not iterable")
        first = self.first.full_repr()
        last = self.last.full_repr()
        diff = map(lambda x, y: x - y, last, first)
        return reduce(lambda x, y: 256 * x + y, diff)


    @classmethod
    def from_mask(cls, first, mask):
        return IPv6Range(first, mask=mask)

    cdef clone_from_cpp(self, cppIPv6Range r):
        del self.ptr
        self.ptr = new cppIPv6Range(r)

    property first:
        def __get__(self):
            return IPv6Address(<bytes>(self.ptr.begin().ref().to_string()))

    property last:
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


cdef class HWRange(object):
    def __cinit__(self, first=None, last=None, only_hosts=False, mask=None):
        cdef cppHWRange r
        if first is None:
            first = HWAddress()
        if not isinstance(first, HWAddress):
            first = HWAddress(bytes(first))
        if mask is None:
            if last is None:
                last = first
            if not isinstance(last, HWAddress):
                last = HWAddress(bytes(last))
            self.ptr = new cppHWRange((<HWAddress>first).ptr[0], (<HWAddress>last).ptr[0], only_hosts)
        else:
            if not isinstance(mask, HWAddress):
                mask = HWAddress(bytes(mask))
            r = hw_range_from_mask((<HWAddress>first).ptr[0], (<HWAddress>mask).ptr[0])
            self.ptr = new cppHWRange(r)

    def __init__(self, first=None, last=None, only_hosts=False, mask=None):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __contains__(self, addr):
        if not isinstance(addr, HWAddress):
            addr = HWAddress(bytes(addr))
        return bool(self.ptr.contains((<HWAddress>addr).ptr[0]))

    cpdef is_iterable(self):
        return bool(self.ptr.is_iterable())

    @classmethod
    def from_mask(cls, first, mask):
        return HWRange(first, mask=mask)

    cdef clone_from_cpp(self, cppHWRange r):
        del self.ptr
        self.ptr = new cppHWRange(r)

    property first:
        def __get__(self):
            return HWAddress(<bytes>(self.ptr.begin().ref().to_string()))

    property last:
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
        if not self.is_iterable():
            raise TypeError("not iterable")
        first = self.first.full_repr()
        last = self.last.full_repr()
        diff = map(lambda x, y: x - y, last, first)
        return reduce(lambda x, y: 256 * x + y, diff)

