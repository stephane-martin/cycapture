# -*- coding: utf-8 -*-

cdef extern from "wrap.h" namespace "Tins" nogil:
    cdef cppclass cppIPv4Range "Tins::WrappedIPv4Range":
        cppIPv4Range()
        cppIPv4Range(const cppIPv4Range& r)
        cppIPv4Range(const cppIPv4Address &first, const cppIPv4Address &last)
        cppIPv4Range(const cppIPv4Address &first, const cppIPv4Address &last, cpp_bool only_hosts)
        cpp_bool contains(const cppIPv4Address &addr) const
        cpp_bool is_iterable() const

        cppclass iterator:
            iterator(const cppIPv4Address &addr)
            const cppIPv4Address& ref "operator*"() const
            cpp_bool operator==(const iterator &rhs) const
            cpp_bool operator!=(const iterator &rhs) const
            iterator& operator++()
        cppclass const_iterator(iterator):
            pass

        cppIPv4Range.const_iterator begin() const
        cppIPv4Range.const_iterator end() const

    cdef cppclass cppIPv6Range "Tins::WrappedIPv6Range":
        cppIPv6Range()
        cppIPv6Range(const cppIPv6Range& r)
        cppIPv6Range(const cppIPv6Address &first, const cppIPv6Address &last)
        cppIPv6Range(const cppIPv6Address &first, const cppIPv6Address &last, cpp_bool only_hosts)
        cpp_bool contains(const cppIPv6Address &addr) const
        cpp_bool is_iterable() const

        cppclass iterator:
            iterator(const cppIPv6Address &addr)
            const cppIPv6Address& ref "operator*"() const
            cpp_bool operator==(const iterator &rhs) const
            cpp_bool operator!=(const iterator &rhs) const
            iterator& operator++()
        cppclass const_iterator(iterator):
            pass

        cppIPv6Range.const_iterator begin() const
        cppIPv6Range.const_iterator end() const

    cdef cppclass cppHWRange "Tins::WrappedHWRange":
        cppHWRange()
        cppHWRange(const cppHWRange& r)
        cppHWRange(const cppHWAddress6 &first, const cppHWAddress6 &last)
        cppHWRange(const cppHWAddress6 &first, const cppHWAddress6 &last, cpp_bool only_hosts)
        cpp_bool contains(const cppHWAddress6 &addr) const
        cpp_bool is_iterable() const

        cppclass iterator:
            iterator(const cppHWAddress6 &addr)
            const cppHWAddress6& ref "operator*"() const
            cpp_bool operator==(const iterator &rhs) const
            cpp_bool operator!=(const iterator &rhs) const
            iterator& operator++()
        cppclass const_iterator(iterator):
            pass

        cppHWRange.const_iterator begin() const
        cppHWRange.const_iterator end() const

    cppIPv4Range ipv4_range_from_mask "Tins::WrappedIPv4Range::from_mask" (const cppIPv4Address &first, const cppIPv4Address &mask)
    cppIPv4Range ipv4_slashrange "Tins::operator/" (const cppIPv4Address &addr, int mask)

    cppIPv6Range ipv6_range_from_mask "Tins::WrappedIPv6Range::from_mask" (const cppIPv6Address &first, const cppIPv6Address &mask)
    cppIPv6Range ipv6_slashrange "Tins::operator/" (const cppIPv6Address &addr, int mask)

    cppHWRange hw_range_from_mask "Tins::WrappedHWRange::from_mask" (const cppHWAddress6 &first, const cppHWAddress6 &mask)
    cppHWRange hw_slashrange "Tins::operator/" (const cppHWAddress6 &addr, int mask)



ctypedef cppIPv4Range.const_iterator ipv4_range_iterator
ctypedef cppIPv6Range.const_iterator ipv6_range_iterator
ctypedef cppHWRange.const_iterator hw_range_iterator



cdef class IPv4Range(object):
    cdef cppIPv4Range* ptr
    cpdef is_iterable(self)
    cdef clone_from_cpp(self, cppIPv4Range r)

cdef class IPv6Range(object):
    cdef cppIPv6Range* ptr
    cpdef is_iterable(self)
    cdef clone_from_cpp(self, cppIPv6Range r)

cdef class HWRange(object):
    cdef cppHWRange* ptr
    cpdef is_iterable(self)
    cdef clone_from_cpp(self, cppHWRange r)
