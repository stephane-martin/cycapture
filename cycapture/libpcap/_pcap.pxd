# -*- coding: utf-8 -*-

"""
Cython bindings for libpcap
"""

from cpython cimport bool

from libc.stdlib cimport malloc, free
from libc.time cimport time
from posix.signal cimport kill
from posix.unistd cimport getpid
from libc.string cimport memcpy, strcpy, strlen
from libc.stdio cimport printf, puts, fdopen, fclose, fopen
from cpython.bytes cimport PyBytes_Check

# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t, uint64_t

# noinspection PyUnresolvedReferences
from cython.view cimport memoryview as cy_memoryview
# noinspection PyUnresolvedReferences
from .._make_mview cimport make_mview_from_const_uchar_buf, mview_get_addr

include "extern_list.pxd.pxi"
include "extern_various.pxd.pxi"
include "extern_pcap.pxd.pxi"
include "pcap_registry.pxd.pxi"
include "utils_func.pxd.pxi"
include "sniffer.pxd.pxi"
include "writer.pxd.pxi"
include "definitions.pxd.pxi"
include "iterator.pxd.pxi"
include "offline_filter.pxd.pxi"

cdef object logger
cdef object LibtinsException

cdef extern from "unistd.h" nogil:
    unsigned csleep "sleep" (unsigned seconds)
