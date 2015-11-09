# -*- coding: utf-8 -*-

from .._pthreadwrap cimport pthread_mutex_t, pthread_hash

cdef pthread_mutex_t* lock

ctypedef struct thread_pcap_node:
    list_head link
    uint32_t thread
    int asked_to_stop
    pcap_t* handle

cdef thread_pcap_node* registry_pcap_get_node() nogil
cdef int registry_pcap_has() nogil
cdef registry_pcap_set(pcap_t* handle)
cdef registry_pcap_unset()
cdef void registry_pcap_set_stopping() nogil
cdef int registry_pcap_has_stopping() nogil
