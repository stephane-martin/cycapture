# -*- coding: utf-8 -*-

cdef class ActivationHelper(object):
    cdef BaseSniffer sniffer_obj
    cdef object old_status

cdef class BaseSniffer(object):
    cdef pcap_t* _handle
    cdef readonly bool activated
    cdef readonly bytes filename
    cdef readonly bytes interface
    cdef public int total
    cdef public int max_p

    cdef int _read_timeout
    cdef int _buffer_size
    cdef int _timestamp_type
    cdef int _timestamp_precision
    cdef int _snapshot_length
    cdef int _direction
    cdef int _promisc_mode
    cdef int _monitor_mode
    cdef char _errbuf[PCAP_ERRBUF_SIZE]
    cdef int _netp
    cdef int _maskp
    cdef bytes _filter
    cdef int _datalink

    cpdef close(self)
    cpdef list_datalinks(self)

    cdef _set_pcap_handle(self)
    cdef _apply_read_timeout(self)
    cdef _apply_buffer_size(self)
    cdef _apply_snapshot_length(self)
    cdef _apply_promisc_mode(self)
    cdef _apply_monitor_mode(self)
    cdef _apply_direction(self)
    cdef _apply_filter(self)
    cdef _apply_datalink(self)
    cdef activate_if_needed(self)
    cdef _pre_activate(self)
    cdef _post_activate(self)
    cdef activate(self)

include "blocking_sniffer.pxd.pxi"
include "nonblocking_sniffer.pxd.pxi"





