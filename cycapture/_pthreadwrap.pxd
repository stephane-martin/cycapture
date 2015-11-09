# -*- coding: utf-8 -*-

from libc.stdlib cimport malloc, free
from libc.string cimport memcpy
# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t, uint64_t

cdef extern from "murmur.h" nogil:
    uint32_t qhashmurmur3_32(void *data, int nbytes)

cdef extern from "pthread.h" nogil:
    ctypedef struct pthread_t:
        pass
    ctypedef struct pthread_attr_t:
        pass
    ctypedef struct pthread_mutex_t:
        pass
    ctypedef struct pthread_mutexattr_t:
        pass

    # Creates a new thread of execution
    int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
    # Marks a thread for deletion
    int pthread_detach(pthread_t thread)
    # Terminates the calling thread
    void pthread_exit(void *value_ptr)
    # Causes the calling thread to wait for the termination of the specified thread.
    int pthread_join(pthread_t thread, void **value_ptr)
    # Cancels execution of a thread.
    int pthread_cancel(pthread_t thread)
    # Calls an initialization routine once.
    # int pthread_once(pthread_once_t *once_control, void (*init_routine)(void))
    # Registers handlers to be called before and after fork()
    int pthread_atfork(void (*prepare)(), void (*parent)(), void (*child)())
    # Returns the thread ID of the calling thread
    pthread_t pthread_self()
    # Compares two thread IDs
    int pthread_equal(pthread_t t1, pthread_t t2)

    int pthread_mutex_init (pthread_mutex_t*, const pthread_mutexattr_t*)
    int pthread_mutex_destroy (pthread_mutex_t*)
    int pthread_mutex_trylock (pthread_mutex_t*)
    int pthread_mutex_lock (pthread_mutex_t*)
    int pthread_mutex_unlock (pthread_mutex_t*)

    int pthread_mutexattr_init (pthread_mutexattr_t*)
    int pthread_mutexattr_destroy (pthread_mutexattr_t*)
    int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *t)
    int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int t)



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

cdef extern from "signal.h" nogil:
    int pthread_kill(pthread_t thread, int sig)

cdef uint32_t pthread_hash(const pthread_t* t=?) nogil
cdef pthread_mutex_t* create_error_check_lock()
cdef destroy_error_check_lock(pthread_mutex_t* l)

cdef class PThread(object):
    cdef pthread_t* thread_ptr
    cdef void cprint(self) nogil
    cpdef tobytes(self)
    cdef equals(self, other)
    cdef int kill(self, int signum) nogil

    @staticmethod
    cdef factory(pthread_t* other)


