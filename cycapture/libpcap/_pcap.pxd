# -*- coding: utf-8 -*-

"""
Cython bindings for libpcap
"""

from cpython cimport bool

from libc.stdlib cimport malloc, free
from libc.time cimport time
from libc.signal cimport signal as libc_signal
from libc.signal cimport SIGUSR1
from posix.signal cimport kill
from posix.unistd cimport getpid
from libc.string cimport memcpy, strcpy, strlen
from libc.stdio cimport printf, puts, fdopen, fclose, fopen

# noinspection PyUnresolvedReferences
from .._make_mview cimport make_mview_from_const_uchar_buf
# noinspection PyUnresolvedReferences
from .._pthreadwrap cimport pthread_kill, pthread_t, pthread_equal, pthread_self, pthread_self_as_bytes, print_thread_id
# noinspection PyUnresolvedReferences
from .._pthreadwrap cimport create_error_check_lock, pthread_mutex_lock, pthread_mutex_unlock, pthread_mutex_t
# noinspection PyUnresolvedReferences
from .._pthreadwrap cimport destroy_error_check_lock, copy_pthread_self

include "extern_list.pxd.pxi"
include "extern_various.pxd.pxi"
include "extern_pcap.pxd.pxi"
include "utils_func.pxd.pxi"
include "sniffer.pxd.pxi"
include "writer.pxd.pxi"
include "definitions.pxd.pxi"
include "iterator.pxd.pxi"

cdef pthread_mutex_t* lock
cdef object logger
cdef object LibtinsException
cdef list_head thread_pcap_global_list
