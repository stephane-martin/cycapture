# -*- coding: utf-8 -*-

cdef extern from "tins/hw_address.h" namespace "Tins" nogil:

    cdef cppclass cppHWAddress6 "Tins::HWAddress<6, uint8_t>":
        cppHWAddress6()
        cppHWAddress6(const unsigned char* ptr) except +ValueError
        cppHWAddress6(const string &) except +ValueError
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

    cdef cppclass cppHWAddress3 "Tins::HWAddress<3, uint8_t>":
        cppHWAddress3()
        cppHWAddress3(const unsigned char* ptr) except +ValueError
        cppHWAddress3(const string &) except +ValueError
        cppHWAddress3(const cppHWAddress3 &) except +ValueError
        const size_t size() const
        string to_string() const
        uint8_t* begin()
        uint8_t* end()
        cpp_bool is_broadcast() const
        cpp_bool is_multicast() const
        cpp_bool is_unicast() const
        cpp_bool equals "operator==" (const cppHWAddress3 &)
        cpp_bool different "operator!=" (const cppHWAddress3 &) const
        cpp_bool less "operator<" (const cppHWAddress3 &) const
        unsigned char operator[](size_t i) const

    const cppHWAddress3 hw3_broadcast "Tins::HWAddress<3, uint8_t>::broadcast"

    cdef cppclass cppHWAddress8 "Tins::HWAddress<8, uint8_t>":
        cppHWAddress8()
        cppHWAddress8(const unsigned char* ptr) except +ValueError
        cppHWAddress8(const string &) except +ValueError
        cppHWAddress8(const cppHWAddress8 &) except +ValueError
        const size_t size() const
        string to_string() const
        uint8_t* begin()
        uint8_t* end()
        cpp_bool is_broadcast() const
        cpp_bool is_multicast() const
        cpp_bool is_unicast() const
        cpp_bool equals "operator==" (const cppHWAddress8 &)
        cpp_bool different "operator!=" (const cppHWAddress8 &) const
        cpp_bool less "operator<" (const cppHWAddress8 &) const
        unsigned char operator[](size_t i) const

    const cppHWAddress8 hw8_broadcast "Tins::HWAddress<8, uint8_t>::broadcast"

    cdef cppclass cppHWAddress16 "Tins::HWAddress<16, uint8_t>":
        cppHWAddress16()
        cppHWAddress16(const unsigned char* ptr) except +ValueError
        cppHWAddress16(const string &) except +ValueError
        cppHWAddress16(const cppHWAddress16 &) except +ValueError
        const size_t size() const
        string to_string() const
        uint8_t* begin()
        uint8_t* end()
        cpp_bool is_broadcast() const
        cpp_bool is_multicast() const
        cpp_bool is_unicast() const
        cpp_bool equals "operator==" (const cppHWAddress16 &)
        cpp_bool different "operator!=" (const cppHWAddress16 &) const
        cpp_bool less "operator<" (const cppHWAddress16 &) const
        unsigned char operator[](size_t i) const

    const cppHWAddress3 hw16_broadcast "Tins::HWAddress<16, uint8_t>::broadcast"


cdef class HWAddress(object):
    cdef cppHWAddress6* ptr
    cpdef is_broadcast(self)
    cpdef is_unicast(self)
    cpdef is_multicast(self)
    cpdef equals(self, other)
    cpdef different(self, other)
    cpdef less(self, other)
    cpdef full_repr(self)
    cpdef to_bytes(self)

