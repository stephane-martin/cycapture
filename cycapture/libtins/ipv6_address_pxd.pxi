# -*- coding: utf-8 -*-

cdef extern from "tins/ip_address.h" namespace "Tins" nogil:
    cdef cppclass cppIPv6Address "Tins::IPv6Address":
        cppIPv6Address()
        cppIPv6Address(const char *addr) except +ValueError
        cppIPv6Address(const string &addr) except +ValueError
        cppIPv6Address(const uint8_t* ptr) except +ValueError
        string to_string() const
        cpp_bool operator==(const cppIPv6Address &rhs) const
        cpp_bool operator!=(const cppIPv6Address &rhs) const
        cpp_bool operator<(const cppIPv6Address &rhs) const
        cpp_bool is_loopback() const
        cpp_bool is_multicast() const
        uint8_t* begin()
        uint8_t* end()

cdef class IPv6Address(object):
    cdef cppIPv6Address* ptr
    cpdef is_loopback(self)
    cpdef is_multicast(self)
    cpdef equals(self, object other)
    cpdef different(self, object other)
    cpdef less(self, object other)
    cpdef full_repr(self)
    cpdef to_buffer(self)
