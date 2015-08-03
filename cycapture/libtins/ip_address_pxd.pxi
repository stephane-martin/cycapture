from libcpp.string cimport string
# noinspection PyUnresolvedReferences
from libcpp cimport bool

cdef extern from "tins/ip_address.h" namespace "Tins":
    # noinspection PyPep8Naming
    cdef cppclass cppIPv4Address "Tins::IPv4Address":
        cppIPv4Address()
        cppIPv4Address(const char*) except +ValueError
        cppIPv4Address(const string &ip) except +ValueError
        cppIPv4Address(unsigned int) except +ValueError
        bool is_loopback() const
        bool is_private() const
        bool is_multicast() const
        bool is_unicast() const
        bool is_broadcast() const
        bool equals "operator==" (const cppIPv4Address &) const
        bool different "operator!=" (const cppIPv4Address &) const
        bool less "operator<" (const cppIPv4Address &) const
        string to_string() const

cdef extern from "wrap.h" namespace "Tins":
    unsigned int convert_to_big_endian_int (cppIPv4Address&)

cdef class IPv4Address(object):
    cdef cppIPv4Address* ptr
    cpdef bool is_loopback(self)
    cpdef bool is_private(self)
    cpdef bool is_broadcast(self)
    cpdef bool is_unicast(self)
    cpdef bool is_multicast(self)
    cpdef equals(self, object other)
    cpdef different(self, object other)
    cpdef less(self, object other)
    cdef cppIPv4Address get_cpp_addr(self)

