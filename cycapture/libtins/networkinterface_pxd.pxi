# -*- coding: utf-8 -*-

cdef extern from "tins/network_interface.h" namespace "Tins" nogil:
    cdef cppclass cppNetworkInterface "Tins::NetworkInterface":
        cppclass Info:
            cppIPv4Address ip_addr, netmask, bcast_addr
            cppHWAddress6 hw_addr

        cppNetworkInterface()
        cppNetworkInterface(const string &name) except +custom_exception_handler
        cppNetworkInterface(const char *name) except +custom_exception_handler
        cppNetworkInterface(cppIPv4Address ip) except +custom_exception_handler
        uint32_t ident "id"() const
        string name() except +custom_exception_handler
        cppNetworkInterface.Info addresses() except +custom_exception_handler
        cpp_bool is_loopback() const
        cpp_bool operator==(const cppNetworkInterface &rhs) const
        cpp_bool operator!=(const cppNetworkInterface &rhs) const
        cpp_bool to_bool "operator bool" () const

    cppNetworkInterface default_interface "Tins::NetworkInterface::default_interface"()
    # noinspection PyUnresolvedReferences
    vector[cppNetworkInterface] all_interfaces "Tins::NetworkInterface::all"()
    cppNetworkInterface network_interface_from_index "Tins::NetworkInterface::from_index"(uint32_t identifier)


cdef class NetworkInterface(object):
    cdef cppNetworkInterface interface
    cpdef is_loopback(self)
    cpdef equals(self, other)

    @staticmethod
    cdef inline factory(cppNetworkInterface* ptr):
        i = NetworkInterface()
        if ptr is not NULL:
            i.interface = ptr[0]
        return i
