# -*- coding: utf-8 -*-


cdef extern from "tins/ip_address.h" namespace "Tins" nogil:
    # noinspection PyPep8Naming
    cdef cppclass cppIPv4Address "Tins::IPv4Address":
        cppIPv4Address()
        cppIPv4Address(const char*) except +ValueError
        cppIPv4Address(const string &ip) except +ValueError
        cppIPv4Address(uint32_t) except +ValueError
        cpp_bool is_loopback() const
        cpp_bool is_private() const
        cpp_bool is_multicast() const
        cpp_bool is_unicast() const
        cpp_bool is_broadcast() const
        cpp_bool equals "operator==" (const cppIPv4Address &) const
        cpp_bool different "operator!=" (const cppIPv4Address &) const
        cpp_bool less "operator<" (const cppIPv4Address &) const
        string to_string() const
        uint32_t to_uint32 "operator uint32_t" () const

#cdef extern from "wrap.h" namespace "Tins" nogil:
#    unsigned int convert_to_big_endian_int (cppIPv4Address&)

cdef class IPv4Address(object):
    cdef cppIPv4Address* ptr
    cpdef is_loopback(self)
    cpdef is_private(self)
    cpdef is_broadcast(self)
    cpdef is_unicast(self)
    cpdef is_multicast(self)
    cpdef equals(self, other)
    cpdef different(self, other)
    cpdef less(self, other)

    @staticmethod
    cdef inline factory(cppIPv4Address* ptr):
        return IPv4Address(ptr.to_string())

