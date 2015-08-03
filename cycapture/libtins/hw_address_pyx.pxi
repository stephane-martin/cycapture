# -*- coding: utf-8 -*-

cdef class HWAddress(object):
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
        pass

    def __str__(self):
        return bytes(self.ptr.to_string())

    def __repr__(self):
        return "HWAddress('{}')".format(bytes(self.ptr.to_string()))

    cpdef bool is_broadcast(self):
        return self.ptr.is_broadcast()

    cpdef bool is_unicast(self):
        return self.ptr.is_unicast()

    cpdef bool is_multicast(self):
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


