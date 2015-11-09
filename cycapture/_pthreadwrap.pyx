# -*- coding: utf-8 -*-

from libc.stdio cimport printf, puts

cdef uint32_t pthread_hash(const pthread_t* t=NULL) nogil:
    cdef pthread_t tid = pthread_self()
    if t is NULL:
        t = &tid
    return qhashmurmur3_32(<void*> t, sizeof(tid))



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


cdef class PThread(object):
    def __cinit__(self):
        self.thread_ptr = <pthread_t*> malloc(sizeof(pthread_t))
        self.thread_ptr[0] = pthread_self()

    def __init__(self):
        pass

    def __dealloc__(self):
        if self.thread_ptr is not NULL:
            free(self.thread_ptr)
            self.thread_ptr = NULL

    cdef void cprint(self) nogil:
        cdef size_t i = 0
        cdef unsigned char *ptc = <unsigned char*> self.thread_ptr
        while i < sizeof(pthread_t):
            printf("%02x", <unsigned>(ptc[i]))
            i += 1
        puts('\n')

    def __str__(self):
        return (<PThread> self).tobytes()

    cpdef tobytes(self):
        return <bytes> ((<unsigned char*> self.thread_ptr)[:sizeof(pthread_t)])

    def __hash__(self):
        return pthread_hash(self.thread_ptr)

    def __richcmp__(self, other, op):
        if op == 2:
            return (<PThread> self).equals(other)
        elif op == 3:
            return not (<PThread> self).equals(other)
        raise ValueError(u"unsupported operation")

    cdef equals(self, other):
        if not isinstance(other, PThread):
            return False
        return str(self) == str(other)

    @staticmethod
    cdef factory(pthread_t* other):
        if other is NULL:
            raise RuntimeError(u"NULL ptr")
        t = PThread()
        memcpy(t.thread_ptr, other, sizeof(pthread_t))
        return t

    cdef int kill(self, int signum) nogil:
        return pthread_kill(self.thread_ptr[0], signum)
