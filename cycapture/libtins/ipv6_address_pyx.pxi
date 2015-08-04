# -*- coding: utf-8 -*-

from libcpp.string cimport string
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t

cdef class IPv6Address(object):
    def __cinit__(self, object addr=None):
        if addr is None:
            self.ptr = new cppIPv6Address()
        elif isinstance(addr, bytes):
            self.ptr = new cppIPv6Address(<string> (<bytes> addr))
        elif isinstance(addr, IPv6Address):
            self.ptr = new cppIPv6Address(<string> str(addr))
        else:
            self.ptr = new cppIPv6Address(<string> (bytes(addr)))

    def __init__(self, object addr=None):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __str__(self):
        return bytes(self.ptr.to_string())

    def __repr__(self):
        return "IPv6Address('{}')".format(bytes(self.ptr.to_string()))

    cpdef cpp_bool is_loopback(self):
        return self.ptr.is_loopback()

    cpdef cpp_bool is_multicast(self):
        return self.ptr.is_multicast()

    def __richcmp__(self, other, op):
        if isinstance(other, bytes):
            other = IPv6Address(other)
        if op == 2:   # equals ==
            return self.equals(other)
        if op == 3:   # different !=
            return self.different(other)
        if not isinstance(other, IPv6Address):
            raise ValueError("can't compare IPv6Address with %s" % type(other))
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
            other = IPv6Address(other)
        if isinstance(other, IPv6Address):
            return self.ptr[0] == (<IPv6Address> other).ptr[0]
        else:
            return False

    cpdef different(self, object other):
        if isinstance(other, bytes):
            other = IPv6Address(other)
        if isinstance(other, IPv6Address):
            return self.ptr[0] != (<IPv6Address> other).ptr[0]
        else:
            return True

    cpdef less(self, object other):
        if isinstance(other, bytes):
            other = IPv6Address(other)
        if isinstance(other, IPv6Address):
            return self.ptr[0] < (<IPv6Address> other).ptr[0]
        else:
            raise ValueError("don't know how to compare")


    def __div__(self, mask):
        if not isinstance(self, IPv6Address):
            raise TypeError("operation not supported")
        r = IPv6Range()
        cdef cppIPv6Range cpp_r = ipv6_slashrange((<IPv6Address>self).ptr[0], <int>int(mask))
        r.clone_from_cpp(cpp_r)
        return r
