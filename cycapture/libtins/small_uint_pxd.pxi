# -*- coding: utf-8 -*-

cdef extern from "wrap.h" namespace "Tins" nogil:
    cdef cppclass small_uint1:
        small_uint1()
        small_uint1(uint8_t) except +ValueError
    cdef cppclass small_uint2:
        small_uint2()
        small_uint2(uint8_t) except +ValueError
    cdef cppclass small_uint4:
        small_uint4()
        small_uint4(uint8_t) except +ValueError
    cdef cppclass small_uint12:
        small_uint12()
        small_uint12(uint16_t) except +ValueError
    cdef cppclass small_uint24:
        small_uint24()
        small_uint24(uint32_t) except +ValueError
