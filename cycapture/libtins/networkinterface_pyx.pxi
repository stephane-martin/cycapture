# noinspection PyUnresolvedReferences
from libcpp cimport bool as cpp_bool
from libcpp.vector cimport vector

cdef class NetworkInterface(object):
    def __cinit__(self, name=None, address=None):
        if name is None and address is None:
            self.ptr = new cppNetworkInterface()
        elif name is not None:
            name = bytes(name)
            self.ptr = new cppNetworkInterface(<string> name)
        else:
            self._make_from_address(address)

    def __init__(self, name=None, address=None):
        pass

    def __dealloc__(self):
        if self.ptr != NULL:
            del self.ptr

    cdef object _make_from_address(self, object address):
        addr = IPv4Address(address)
        self.ptr = new cppNetworkInterface(addr.ptr[0])

    cpdef int ident(self):
        return int(self.ptr.ident())

    cpdef bytes name(self):
        return <bytes> self.ptr.name()

    cpdef object addresses(self):
        cdef cppNetworkInterface.Info infos = self.ptr.addresses()
        # Info:
        # CPPIPV4Address ip_addr, netmask, bcast_addr
        # HWAddress6 hw_addr
        return {
            'ip_addr': IPv4Address(convert_to_big_endian_int(infos.ip_addr)),
            'netmask': IPv4Address(convert_to_big_endian_int(infos.netmask)),
            'bcast_addr': IPv4Address(convert_to_big_endian_int(infos.bcast_addr)),
            'hw_addr': HWAddress(infos.hw_addr.to_string())
        }

    cpdef cpp_bool is_loopback(self):
        return self.ptr.is_loopback()

    def __bool__(self):
        return network_interface_to_bool(self.ptr[0])

    @classmethod
    def default(cls):
        cdef cppNetworkInterface default_i = default_interface()
        interface = NetworkInterface(default_i.name())
        return interface

    @classmethod
    def all(cls):
        cdef vector[cppNetworkInterface] all_i = all_interfaces()
        return [NetworkInterface(interface_i.name()) for interface_i in all_i]

    def __str__(self):
        return self.name()

    def __repr__(self):
        return "NetworkInterface('{}')".format(self.name())

