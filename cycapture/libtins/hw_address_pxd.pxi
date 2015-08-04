# -*- coding: utf-8 -*-

from libcpp.string cimport string

cdef extern from "tins/hw_address.h" namespace "Tins" nogil:
    # noinspection PyPep8Naming
    cdef cppclass cppHWAddress6 "Tins::HWAddress<6, uint8_t>":
        cppHWAddress6()
        cppHWAddress6(const unsigned char* ptr) except +ValueError
        cppHWAddress6(const string &) except +ValueError
        cppHWAddress6(const char (&address)[6]) except +ValueError
        cppHWAddress6(const cppHWAddress6 &) except +ValueError
        const size_t size() const
        string to_string() const
        uint8_t* begin()
        uint8_t* end()
        cpp_bool is_broadcast() const
        cpp_bool is_multicast() const
        cpp_bool is_unicast() const
        cpp_bool equals "operator==" (const cppHWAddress6 &)
        cpp_bool different "operator!=" (const cppHWAddress6 &) const
        cpp_bool less "operator<" (const cppHWAddress6 &) const
        unsigned char operator[](size_t i) const

    const cppHWAddress6 hw6_broadcast "Tins::HWAddress<6, uint8_t>::broadcast"

cdef class HWAddress(object):
    cdef cppHWAddress6* ptr
    cpdef cpp_bool is_broadcast(self)
    cpdef cpp_bool is_unicast(self)
    cpdef cpp_bool is_multicast(self)
    cpdef equals(self, object other)
    cpdef different(self, object other)
    cpdef less(self, object other)
    cpdef full_repr(self)

