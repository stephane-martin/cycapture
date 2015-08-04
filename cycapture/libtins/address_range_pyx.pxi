# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t
from libcpp.vector cimport vector
from libcpp.list cimport list as cpp_list
from cython.operator cimport dereference as deref, preincrement as inc
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free

cdef class IPv4Range(object):
    def __cinit__(self, first=None, last=None, only_hosts=False, mask=None):
        cdef cppIPv4Range r
        if first is None:
            first = IPv4Address()
        if not isinstance(first, IPv4Address):
            first = IPv4Address(bytes(first))
        if mask is None:
            if last is None:
                last = first
            if not isinstance(last, IPv4Address):
                last = IPv4Address(bytes(last))
            self.ptr = new cppIPv4Range((<IPv4Address>first).ptr[0], (<IPv4Address>last).ptr[0], only_hosts)
        else:
            if not isinstance(mask, IPv4Address):
                mask = IPv4Address(bytes(mask))
            r = ipv4range_from_mask((<IPv4Address>first).ptr[0], (<IPv4Address>mask).ptr[0])
            self.ptr = new cppIPv4Range(r)

    def __init__(self, first=None, last=None, only_hosts=False, mask=None):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    def __contains__(self, addr):
        if not isinstance(addr, IPv4Address):
            addr = IPv4Address(bytes(addr))
        return bool(self.ptr.contains((<IPv4Address>addr).ptr[0]))

    cpdef is_iterable(self):
        return bool(self.ptr.is_iterable())

    @classmethod
    def from_mask(cls, first, mask):
        return IPv4Range(first, mask=mask)

    cdef clone_from_cpp_range(self, cppIPv4Range r):
        del self.ptr
        self.ptr = new cppIPv4Range(r)

    property first:
        def __get__(self):
            return IPv4Address(<bytes>(self.ptr.begin().ref().to_string()))

    property last:
        def __get__(self):
            return IPv4Address(<bytes>(self.ptr.end().ref().to_string()))

    def __iter__(self):
        # please, don't ask why :(
        cdef range_iterator* it = <range_iterator*> PyMem_Malloc(sizeof(range_iterator))
        if it is NULL:
            raise MemoryError()
        try:
            it[0] = self.ptr.begin()
            while it[0] != self.ptr.end():
                yield IPv4Address(it[0].ref().to_string())
                inc(it[0])
        finally:
            PyMem_Free(it)
