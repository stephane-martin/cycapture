# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from libcpp cimport bool
from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.list cimport list

include "ip_address.pyx"
include "hw_address.pyx"
include "pdu.pyx"
include "ip.pyx"
include "networkinterface.pyx"

#cdef EthernetII* eth = new EthernetII()
#cdef pointer p = eth.find_pdu[EthernetII]()
#print(p==NULL)
#print(p.header_size())

#cdef NetworkInterface d = default_interface()
#print(d.name())
#print(network_interface_to_bool(d))

