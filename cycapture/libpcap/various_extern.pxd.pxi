
cdef extern from "stdio.h" nogil:
    ctypedef struct FILE

cdef extern from "signal.h" nogil:
    ctypedef int sigset_t
    int sigaddset(sigset_t *s, int signo)
    int sigdelset(sigset_t *s, int signo)
    int sigemptyset(sigset_t *s)
    int sigfillset(sigset_t *s)
    int sigismember(const sigset_t *s, int signo)
    int pthread_sigmask(int how, const sigset_t* s, sigset_t *oset)
    int siginterrupt(int sig, int flag)
    int SIG_SETMASK, SIG_UNBLOCK, SIG_BLOCK

cdef extern from "sys/time.h":
    struct timeval:
        long tv_sec
        int tv_usec

cdef extern from "sys/types.h":
    struct sockaddr:
        unsigned char sa_family
        unsigned char sa_len
        char sa_data[14]
    struct in_addr:
        unsigned int s_addr
    struct in6_addr:
        pass
    struct sockaddr_in:
        unsigned char sin_len
        in_addr sin_addr
    struct sockaddr_in6:
        unsigned char sin6_len
        in6_addr sin6_addr

    enum: INET_ADDRSTRLEN
    enum: INET6_ADDRSTRLEN

cdef extern from "netdb.h":
    enum: NI_MAXHOST
    enum: NI_NUMERICHOST
    enum: NI_MAXSERV
    enum: NI_NUMERICSERV
    int getnameinfo(const sockaddr*, unsigned int, char*, unsigned int, char*, unsigned int, int)

cdef extern from "arpa/inet.h":
    const char* inet_ntop(int, const void*, char*, unsigned int)

