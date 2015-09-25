# -*- coding: utf-8 -*-

cdef class SniffingIterator(object):
    cdef BlockingSniffer sniffer
    cdef object queue
    cdef object thread
    cdef object f
    cdef int max_p
    cdef int total_returned
    cdef int cache_size

    cpdef start(self)
    cpdef stop(self)
