# -*- coding: utf-8 -*-

cimport libtins_exceptions

from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_Check, PyBytes_Size
from cpython.tuple cimport PyTuple_Check
from cpython.list cimport PyList_Check
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free

# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t

from libcpp.vector cimport vector
from libcpp.list cimport list as cpp_list
from libcpp.pair cimport pair
from libcpp.string cimport string
# noinspection PyUnresolvedReferences
from libcpp cimport bool as cpp_bool
from libcpp.map cimport map as cpp_map
from libcpp.set cimport set as cpp_set

# noinspection PyUnresolvedReferences
from cython.operator cimport dereference as deref
# noinspection PyUnresolvedReferences
from cython.operator cimport preincrement as inc
# noinspection PyUnresolvedReferences
from cython.view cimport memoryview as cy_memoryview


# noinspection PyUnresolvedReferences
from ..make_mview cimport make_mview_from_const_uchar_buf, make_mview_from_uchar_buf, mview_get_addr

cdef extern from "custom_exception_handler.h" namespace "Cycapture":
    cdef void custom_exception_handler()

include "ipv4_address_pxd.pxi"
include "ipv6_address_pxd.pxi"
include "hw_address_pxd.pxi"
include "address_range_pxd.pxi"
include "networkinterface_pxd.pxi"
include "utils_pxd.pxi"
include "pdu_pxd.pxi"
include "ethernet_pxd.pxi"
include "ip_pxd.pxi"
include "tcp_pxd.pxi"
include "udp_pxd.pxi"
include "raw_pxd.pxi"
include "dns_pxd.pxi"
