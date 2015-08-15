# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
IF UNAME_SYSNAME == "Linux":
    cdef extern from "pthread.h" nogil:
        ctypedef unsigned long int pthread_t

ELSE:
    # BSD, DARWIN...
    cdef extern from "pthread.h" nogil:
        ctypedef struct pthread_t:
            pass

cdef extern from "pthread.h" nogil:
    int pthread_kill(pthread_t thread, int sig)
    pthread_t pthread_self()
    int pthread_equal(pthread_t t1, pthread_t t2)

cdef class PthreadWrap(object):
    cdef pthread_t thread_id
    cpdef as_bytes(self)

cpdef int thread_kill(PthreadWrap thread, int sig) nogil
cdef pthread_t get_thread_id() nogil
cpdef void print_thread_id() nogil
