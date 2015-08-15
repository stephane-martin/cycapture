# -*- coding: utf-8 -*-

from libc.stdio cimport printf, puts

cdef class PthreadWrap(object):
    def __cinit__(self):
        self.thread_id = pthread_self()

    def __dealloc__(self):
        pass

    def __init__(self):
        pass

    cpdef as_bytes(self):
        return <bytes> (<unsigned char*>(<void*>(&self.thread_id)))[:sizeof(self.thread_id)]


cpdef int thread_kill(PthreadWrap thread, int sig) nogil:
    return pthread_kill(thread.thread_id, sig)

# noinspection PyUnresolvedReferences
cdef pthread_t get_thread_id() nogil:
    return pthread_self()

cpdef void print_thread_id() nogil:
    cdef size_t i = 0
    cdef pthread_t ident = pthread_self()
    cdef unsigned char *ptc = <unsigned char*>(<void*>(&ident))
    while i < sizeof(ident):
        printf("%02x", <unsigned>(ptc[i]))
        i += 1
    puts('\n')
