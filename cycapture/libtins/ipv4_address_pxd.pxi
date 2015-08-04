# -*- coding: utf-8 -*-

from libcpp.string cimport string
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t
# noinspection PyUnresolvedReferences
from libcpp cimport bool as cpp_bool


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

cdef extern from "wrap.h" namespace "Tins" nogil:
    unsigned int convert_to_big_endian_int (cppIPv4Address&)

cdef class IPv4Address(object):
    cdef cppIPv4Address* ptr
    cpdef cpp_bool is_loopback(self)
    cpdef cpp_bool is_private(self)
    cpdef cpp_bool is_broadcast(self)
    cpdef cpp_bool is_unicast(self)
    cpdef cpp_bool is_multicast(self)
    cpdef equals(self, object other)
    cpdef different(self, object other)
    cpdef less(self, object other)
