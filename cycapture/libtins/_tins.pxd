# -*- coding: utf-8 -*-

"""
Cython module for libtins
"""

from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_Check, PyBytes_Size
from cpython.tuple cimport PyTuple_Check
from cpython.list cimport PyList_Check
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free
from cpython.sequence cimport PySequence_Check
from cpython.iterator cimport PyIter_Check

# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t, uint64_t

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
from .._make_mview cimport make_mview_from_const_uchar_buf, make_mview_from_uchar_buf, mview_get_addr

# noinspection PyUnresolvedReferences
from ._py_exceptions cimport custom_exception_handler
from ._py_exceptions import LibtinsException, MalformedAddress, MalformedPacket, MalformedOption, OptionNotFound
from ._py_exceptions import OptionPayloadTooLarge, FieldNotPresent, PDUNotFound, InvalidInterface, UnknownLinkType
from ._py_exceptions import SocketOpenError, SocketCloseError, SocketWriteError, InvalidSocketType, BadTinsCast
from ._py_exceptions import ProtocolDisabled, MemoryViewFormat

#cdef extern from "custom_exception_handler.h" namespace "Tins":
#    cdef void custom_exception_handler()


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
include "icmp_pxd.pxi"
include "ipv4_reassembler_pxd.pxi"
include "datalink_pxd.pxi"
include "packet_sender_pxd.pxi"
include "tcp_stream_pxd.pxi"
include "tcp_stream_follower_pxd.pxi"
