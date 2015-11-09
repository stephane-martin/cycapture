# -*- coding: utf-8 -*-

cpdef void block_sig_except(int signo) nogil:
    """
    block_sig_except(int signo)
    Set a signal mask that blocks all signals except `signo`.

    Parameters
    ----------
    signo: int
        the signal to let pass
    """
    cdef sigset_t s
    sigfillset(&s)
    pthread_sigmask(SIG_BLOCK, &s, NULL)
    sigemptyset(&s)
    sigaddset(&s, signo)
    pthread_sigmask(SIG_UNBLOCK, &s, NULL)

cpdef void set_sig_interrupt(int signo) nogil:
    """
    set_sig_interrupt(int signo)
    Allow the given signal to interrupt system calls.

    Parameters
    ----------
    signo: signal number
    """
    siginterrupt(signo, 1)

cpdef void unset_sig_interrupt(int signo) nogil:
    """
    unset_sig_interrupt(int signo)
    Don't allow the given signal to interrupt system calls.

    Parameters
    ----------
    signo: signal number
    """
    siginterrupt(signo, 0)

cdef int set_sigaction(int signum, void (*sa_sigaction)(int, siginfo_t*, void*)) nogil:
    cdef sigaction action
    cdef sigaction old_sigaction
    action.sa_sigaction = sa_sigaction
    action.sa_flags = SA_SIGINFO
    cdef int res = c_sigaction(signum, &action, &old_sigaction)
    return res


cdef class Sigaction(object):
    def __cinit__(self):
        pass
    def __init__(self):
        pass
    def __dealloc__(self):
        pass

    cdef set_normal_handler(self, sighandler_t h):
        if self.native.sa_sigaction is not NULL:
            raise RuntimeError(u"you can't specify both a normal and a sigaction handler")
        self.native.sa_handler = h

    cdef set_sigaction_handler(self, sigaction_handler_t h):
        if self.native.sa_handler is not NULL:
            raise RuntimeError(u"you can't specify both a normal and a sigaction handler")
        self.native.sa_sigaction = h

    cdef Sigaction set_for_signum(self, int signum):
        self.native.sa_flags = SA_SIGINFO if self.native.sa_sigaction is not NULL else 0
        cdef Sigaction old_sigaction_obj = Sigaction()
        cdef int res = c_sigaction(signum, &self.native, &old_sigaction_obj.native)
        if res == 0:
            return old_sigaction_obj
        raise RuntimeError("c_sigaction failed")


