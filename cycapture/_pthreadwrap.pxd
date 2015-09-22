# -*- coding: utf-8 -*-

from libc.stdlib cimport malloc, free
from libc.string cimport memcpy

cdef extern from "pthread.h" nogil:
    ctypedef struct pthread_t:
        pass
    ctypedef struct pthread_mutex_t:
        pass
    ctypedef struct pthread_mutexattr_t:
        pass

    int pthread_mutex_init (pthread_mutex_t*, const pthread_mutexattr_t*)
    int pthread_mutex_destroy (pthread_mutex_t*)
    int pthread_mutex_trylock (pthread_mutex_t*)
    int pthread_mutex_lock (pthread_mutex_t*)
    int pthread_mutex_unlock (pthread_mutex_t*)

    int pthread_mutexattr_init (pthread_mutexattr_t*)
    int pthread_mutexattr_destroy (pthread_mutexattr_t*)
    int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *t)
    int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int t)

    int pthread_kill(pthread_t thread, int sig)
    pthread_t pthread_self()
    int pthread_equal(pthread_t t1, pthread_t t2)

    # robust mutex dont exist on mac osx :(
    # int pthread_mutexattr_getrobust(const pthread_mutexattr_t *attr, int *robust)
    # int pthread_mutexattr_setrobust(pthread_mutexattr_t *attr, int robust)
    # int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr, int *pshared)
    # int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared)
    # enum:
    #     PTHREAD_MUTEX_STALLED
    #     PTHREAD_MUTEX_ROBUST

    enum:
        PTHREAD_MUTEX_NORMAL
        PTHREAD_MUTEX_ERRORCHECK
        PTHREAD_MUTEX_RECURSIVE
        PTHREAD_MUTEX_DEFAULT

cpdef void print_thread_id() nogil
cpdef bytes pthread_self_as_bytes()
cdef pthread_t* copy_pthread_self()
cdef pthread_mutex_t* create_error_check_lock()
cdef destroy_error_check_lock(pthread_mutex_t* l)
