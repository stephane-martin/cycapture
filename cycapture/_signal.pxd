# -*- coding: utf-8 -*-

DEF ON_WINDOWS = UNAME_SYSNAME == "Windows"

cdef extern from "signal.h" nogil:
    ctypedef struct siginfo_t:
        int si_signo
        int si_errno
        int si_code
        int si_pid
        int si_uid
        int si_status

ctypedef void (*sighandler_t)(int s) nogil                                      # normal signal handler
ctypedef void (*sigaction_handler_t)(int s, siginfo_t* info, void* unused)      # sigaction signal handler

cdef extern from "signal.h" nogil:
    # signal sets
    ctypedef struct sigset_t:
        pass

    # sa_mask specifies a mask of signals which should be blocked during  execution of the signal handler. In addition,
    # the signal which triggered the handler will be blocked, unless the SA_NODEFER flag is used.
    struct sigaction:
        void (*sa_handler)(int)                                     # never set both sa_handler and sa_sigaction
        void (*sa_sigaction)(int, siginfo_t*, void*)
        sigset_t sa_mask
        int sa_flags

    sighandler_t c_signal "signal" (int sig, sighandler_t func)                 # not really portable... use sigaction instead
    int c_sigaction "sigaction" (int sig, const sigaction* act, sigaction* oact)
    int raise_signal "raise" (int signum)

    int sigaddset(sigset_t *s, int signo)                           # adds the specified signal signo to the signal set
    int sigdelset(sigset_t *s, int signo)                           # deletes the specified signal signo from the signal set
    int sigemptyset(sigset_t *s)                                    # initializes a signal set to be empty
    int sigfillset(sigset_t *s)                                     # initializes a signal set to contain all signals
    int sigismember(const sigset_t *s, int signo)                   # returns whether a specified signal signo is contained in the signal set
    int pthread_sigmask(int how, const sigset_t* s, sigset_t *oset) # examines and/or changes the calling thread's signal mask
    int siginterrupt(int sig, int flag)                             # allow signals to interrupt system calls

    cdef enum:
        # enum for signal sets
        SIG_SETMASK
        SIG_UNBLOCK
        SIG_BLOCK

        # predefined signal handlers
        SIG_DFL
        SIG_IGN

        # sigaction flags
        SA_SIGINFO              # use sa_sigaction instead of sa_handler
        SA_NOCLDSTOP
        SA_NOCLDWAIT
        SA_NODEFER              # Do not prevent the signal from being received from within its own signal handler
        SA_ONSTACK
        SA_RESETHAND            # Restore the signal action to the default upon entry to the signal handler
        SA_RESTART              # make certain system calls restartable across signals

        # signal types
        SIGHUP
        SIGINT
        SIGQUIT
        SIGILL
        SIGTRAP
        SIGABRT
        SIGEMT
        SIGFPE
        SIGKILL
        SIGBUS
        SIGSEGV
        SIGSYS
        SIGPIPE
        SIGALRM
        SIGTERM
        SIGURG
        SIGSTOP
        SIGTSTP
        SIGCONT
        SIGCHLD
        SIGTTIN
        SIGTTOU
        SIGIO
        SIGXCPU
        SIGXFSZ
        SIGVTALRM
        SIGPROF
        SIGWINCH
        SIGINFO
        SIGUSR1
        SIGUSR2


cpdef void block_sig_except(int signo) nogil
cpdef void set_sig_interrupt(int signo) nogil
cpdef void unset_sig_interrupt(int signo) nogil
cdef int set_sigaction(int signum, void (*sa_sigaction)(int, siginfo_t*, void*)) nogil

cdef class Sigaction(object):
    cdef sigaction native
    cdef set_normal_handler(self, sighandler_t h)
    cdef set_sigaction_handler(self, sigaction_handler_t h)
    cdef Sigaction set_for_signum(self, int signum)


