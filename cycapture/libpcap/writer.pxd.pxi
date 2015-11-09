# -*- coding: utf-8 -*-

cdef class PacketWriter(object):
    cdef object output
    cdef int linktype
    cdef pcap_t* handle
    cdef pcap_dumper_t* dumper
    cdef unsigned char close_file_on_dealloc
    cdef pthread_mutex_t* output_lock

    cpdef write(self, object buf, long tv_sec=?, int tv_usec=?)
    cdef int write_uchar_buf(self, unsigned char* buf, int length, long tv_sec=?, int tv_usec=?) nogil
    cdef _clean(self)
    cpdef open(self)
    cpdef close(self)

cdef class NonBlockingPacketWriter(PacketWriter):
    cdef object q
    cdef int stopping
