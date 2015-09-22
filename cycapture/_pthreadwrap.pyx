# -*- coding: utf-8 -*-

from libc.stdio cimport printf, puts

cpdef bytes pthread_self_as_bytes():
    cdef pthread_t tid = pthread_self()
    return <bytes> (<unsigned char*>(<void*>(&tid)))[:sizeof(tid)]

cpdef void print_thread_id() nogil:
    cdef size_t i = 0
    cdef pthread_t ident = pthread_self()
    cdef unsigned char *ptc = <unsigned char*>(<void*>(&ident))
    while i < sizeof(ident):
        printf("%02x", <unsigned>(ptc[i]))
        i += 1
    puts('\n')

cdef pthread_t* copy_pthread_self():
    cdef pthread_t tid = pthread_self()
    cdef pthread_t* copy = <pthread_t*> malloc(sizeof(pthread_t))
    memcpy(copy, &tid, sizeof(pthread_t))
    return copy

cdef pthread_mutex_t* create_error_check_lock():
    cdef pthread_mutex_t* lock = <pthread_mutex_t*> malloc(sizeof(pthread_mutex_t))
    cdef pthread_mutexattr_t* mattr = <pthread_mutexattr_t*> malloc(sizeof(pthread_mutexattr_t))
    cdef int res
    res = pthread_mutexattr_init(mattr)
    res = pthread_mutexattr_settype(mattr, PTHREAD_MUTEX_ERRORCHECK)
    res = pthread_mutex_init(lock, mattr)
    pthread_mutexattr_destroy(mattr)
    free(mattr)
    return lock

cdef destroy_error_check_lock(pthread_mutex_t* l):
    pthread_mutex_destroy(l)
    free(l)
