# encoding: utf-8

cdef class IPv4Address(object):
    broadcast = IPv4Address("255.255.255.255")

    def __cinit__(self, object addr=None):
        if addr is None:
            self.ptr = new cppIPv4Address(<const char*> NULL)
        elif isinstance(addr, int):
            self.ptr = new cppIPv4Address(<uint32_t> addr)
        elif isinstance(addr, bytes):
            self.ptr = new cppIPv4Address(<string> (<bytes> addr))
        elif isinstance(addr, IPv4Address):
            self.ptr = new cppIPv4Address(convert_to_big_endian_int((<IPv4Address> addr).ptr[0]))
        else:
            self.ptr = new cppIPv4Address(<string> (bytes(addr)))

    def __init__(self, object addr=None):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __str__(self):
        return bytes(self.ptr.to_string())

    def __repr__(self):
        return "IPv4Address('{}')".format(bytes(self.ptr.to_string()))

    cpdef cpp_bool is_loopback(self):
        return self.ptr.is_loopback()

    cpdef cpp_bool is_private(self):
        return self.ptr.is_private()

    cpdef cpp_bool is_broadcast(self):
        return self.ptr.is_broadcast()

    cpdef cpp_bool is_unicast(self):
        return self.ptr.is_unicast()

    cpdef cpp_bool is_multicast(self):
        return self.ptr.is_multicast()

    def __richcmp__(self, other, op):
        if isinstance(other, bytes):
            other = IPv4Address(other)
        if op == 2:   # equals ==
            return self.equals(other)
        if op == 3:   # different !=
            return self.different(other)
        if not isinstance(other, IPv4Address):
            raise ValueError("can't compare IPv4Address with %s" % type(other))
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
            other = IPv4Address(other)
        if isinstance(other, IPv4Address):
            return self.ptr.equals((<IPv4Address> other).ptr[0])
        else:
            return False

    cpdef different(self, object other):
        if isinstance(other, bytes):
            other = IPv4Address(other)
        if isinstance(other, IPv4Address):
            return self.ptr.different((<IPv4Address> other).ptr[0])
        else:
            return True

    cpdef less(self, object other):
        if isinstance(other, bytes):
            other = IPv4Address(other)
        if isinstance(other, IPv4Address):
            return self.ptr.less((<IPv4Address> other).ptr[0])
        else:
            raise ValueError("don't know how to compare")

    def __int__(self):
        return int(convert_to_big_endian_int(self.ptr[0]))


