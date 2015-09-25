# -*- coding: utf-8 -*-

cdef class OfflineFilter(object):
    cdef pcap_t* handle
    cdef bpf_program program

    cdef bint match(self, const uint8_t *pkt, int size) except -1
    cpdef bint match_pdu(self, object pdu) except -1
    cpdef bint match_buffer(self, object buf) except -1
    cdef bint call_freecode
