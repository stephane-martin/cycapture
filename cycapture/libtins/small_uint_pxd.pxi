# -*- coding: utf-8 -*-

cdef extern from "tins/small_uint.h" namespace "Tins" nogil:
    cdef cppclass small_uint1 "Tins::small_uint<1>":
        small_uint1()
        small_uint1(uint8_t) except +ValueError
    cdef cppclass small_uint2 "Tins::small_uint<2>":
        small_uint2()
        small_uint2(uint8_t) except +ValueError
    cdef cppclass small_uint3 "Tins::small_uint<3>":
        small_uint3()
        small_uint3(uint8_t) except +ValueError
    cdef cppclass small_uint4 "Tins::small_uint<4>":
        small_uint4()
        small_uint4(uint8_t) except +ValueError
    cdef cppclass small_uint7 "Tins::small_uint<7>":
        small_uint7()
        small_uint7(uint8_t) except +ValueError
    cdef cppclass small_uint12 "Tins::small_uint<12>":
        small_uint12()
        small_uint12(uint16_t) except +ValueError
    cdef cppclass small_uint24 "Tins::small_uint<24>":
        small_uint24()
        small_uint24(uint32_t) except +ValueError
