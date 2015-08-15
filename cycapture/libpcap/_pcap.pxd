# -*- coding: utf-8 -*-

"""
Cython bindings for libpcap
"""

from cpython cimport bool
# noinspection PyUnresolvedReferences
from ..make_mview cimport make_mview_from_const_uchar_buf
# noinspection PyUnresolvedReferences
from ..pthreadwrap cimport PthreadWrap, thread_kill, get_thread_id, pthread_t, pthread_equal, print_thread_id

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

cdef extern from "pcap/bpf.h":
    struct bpf_insn:
        unsigned short code;
        unsigned char jt;
        unsigned char jf;
        unsigned int k;
    struct bpf_program:
        unsigned int bf_len
        bpf_insn* bf_insns

cdef extern from "pcap/pcap.h":
    ctypedef struct pcap_t:
        pass

    struct pcap_addr:
        pcap_addr* next
        sockaddr* addr
        sockaddr* netmask
        sockaddr* broadaddr
        sockaddr* dstaddr
    ctypedef pcap_addr pcap_addr_t

    struct pcap_pkthdr:
        timeval ts
        unsigned int caplen
        unsigned int len

    struct pcap_if:
        pcap_if* next
        char* name
        char* description
        pcap_addr* addresses
        unsigned int flags
    ctypedef pcap_if pcap_if_t

    enum: PCAP_NETMASK_UNKNOWN

ctypedef pcap_pkthdr pcap_pkthdr_t
ctypedef bpf_program bpf_program_t
# noinspection PyUnresolvedReferences
ctypedef void (*pcap_handler) (unsigned char*, const pcap_pkthdr_t*, const unsigned char*)

cdef extern from "pcap/pcap.h" nogil:
    ctypedef enum pcap_direction_t:
        PCAP_D_INOUT,
        PCAP_D_IN,
        PCAP_D_OUT
    pcap_t *pcap_create(const char*, char*)
    int pcap_set_snaplen(pcap_t*, int)
    int pcap_set_timeout(pcap_t *, int)
    int pcap_set_tstamp_type(pcap_t*, int)
    int pcap_set_immediate_mode(pcap_t*, int)
    int pcap_set_buffer_size(pcap_t*, int)
    int pcap_set_tstamp_precision(pcap_t*, int)
    int pcap_get_tstamp_precision(pcap_t*)
    int pcap_set_promisc(pcap_t *p, int promisc)
    int pcap_can_set_rfmon(pcap_t *p)
    int pcap_set_rfmon(pcap_t *p, int rfmon)
    int pcap_activate(pcap_t*)
    pcap_t* pcap_open_live(const char*, int, int, int, char*)
    int pcap_dispatch(pcap_t*, int, pcap_handler, unsigned char*)
    int pcap_loop(pcap_t*, int, pcap_handler, unsigned char*)
    void pcap_close(pcap_t*)
    const unsigned char* pcap_next(pcap_t*, pcap_pkthdr*)
    int pcap_next_ex(pcap_t*, pcap_pkthdr**, const unsigned char**)
    void pcap_breakloop(pcap_t*)
    int pcap_setdirection(pcap_t*, pcap_direction_t)
    int pcap_getnonblock(pcap_t*, char*)
    int pcap_setnonblock(pcap_t*, int, char*)
    const char* pcap_statustostr(int)
    const char* pcap_strerror(int)
    char* pcap_geterr(pcap_t*)
    void pcap_perror(pcap_t*, char*)
    int pcap_datalink(pcap_t*)
    int pcap_datalink_ext(pcap_t*)
    int pcap_list_datalinks(pcap_t*, int**)
    int pcap_set_datalink(pcap_t*, int)
    void pcap_free_datalinks(int*)
    int pcap_datalink_name_to_val(const char*)
    const char* pcap_datalink_val_to_name(int)
    const char* pcap_datalink_val_to_description(int)
    int pcap_major_version(pcap_t*)
    int pcap_minor_version(pcap_t*)
    int pcap_get_selectable_fd(pcap_t*)
    const char* pcap_lib_version()
    char* pcap_lookupdev(char *errbuf)
    int pcap_findalldevs(pcap_if_t** alldevsp, char* errbuf)
    void pcap_freealldevs(pcap_if_t* alldevs)
    int pcap_lookupnet(const char *device, unsigned int *netp, unsigned int *maskp, char *errbuf)
    int pcap_list_tstamp_types(pcap_t *p, int **tstamp_typesp)
    void pcap_free_tstamp_types(int *tstamp_types)
    int pcap_compile(pcap_t *p, bpf_program *fp, const char*, int optimize, unsigned int netmask)
    void pcap_freecode(bpf_program*)
    int pcap_setfilter(pcap_t *p, bpf_program *fp)


cdef enum:
    PCAP_WARNING = 1
    PCAP_WARNING_PROMISC_NOTSUP = 2
    PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3
    PCAP_ERROR = -1
    PCAP_ERROR_BREAK = -2
    PCAP_ERROR_NOT_ACTIVATED = -3
    PCAP_ERROR_ACTIVATED = -4
    PCAP_ERROR_NO_SUCH_DEVICE = -5
    PCAP_ERROR_RFMON_NOTSUP = -6
    PCAP_ERROR_NOT_RFMON = -7
    PCAP_ERROR_PERM_DENIED = -8
    PCAP_ERROR_IFACE_NOT_UP = -9
    PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10
    PCAP_ERROR_PROMISC_PERM_DENIED = -11
    PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12
    AF_INET = 2
    AF_LINK = 18
    AF_INET6 = 30
    PCAP_IF_LOOPBACK = 0x00000001
    PCAP_IF_UP = 0x00000002
    PCAP_IF_RUNNING = 0x00000004
    PCAP_ERRBUF_SIZE = 256
    PCAP_TSTAMP_PRECISION_MICRO	= 0
    PCAP_TSTAMP_PRECISION_NANO = 1
    PCAP_TSTAMP_HOST = 0
    PCAP_TSTAMP_HOST_LOWPREC = 1
    PCAP_TSTAMP_HOST_HIPREC = 2
    PCAP_TSTAMP_ADAPTER = 3
    PCAP_TSTAMP_ADAPTER_UNSYNCED = 4


cpdef object lookupdev()
cpdef object findalldevs()
cpdef object lookupnet(bytes device)

ctypedef void (*c_callback) (long tv_sec, int tv_usec, int caplen, int length, const unsigned char* pkt, void* p) nogil

ctypedef struct dispatch_user_param:
    c_callback fun
    void* param

cdef class ActivationHelper(object):
    cdef Sniffer sniffer_obj
    cdef object old_status

cdef class Sniffer(object):
    cdef readonly bool activated
    cdef int _read_timeout
    cdef int _buffer_size
    cdef int _timestamp_type
    cdef int _timestamp_precision
    cdef int _snapshot_length
    cdef int _direction
    cdef int _promisc_mode
    cdef int _monitor_mode
    cdef readonly bytes source
    cdef char _errbuf[PCAP_ERRBUF_SIZE]
    cdef pcap_t* _handle
    cdef int _netp
    cdef int _maskp
    cdef bytes _filter
    cdef int _datalink

    cpdef close(self)
    cdef _apply_read_timeout(self)
    cdef _apply_buffer_size(self)
    cdef _apply_snapshot_length(self)
    cdef _apply_promisc_mode(self)
    cdef _apply_monitor_mode(self)
    cdef _apply_direction(self)
    cdef _apply_filter(self)
    cdef _apply_datalink(self)
    cpdef list_datalinks(self)
    cdef _activate_if_needed(self)
    cdef _pre_activate(self)
    cdef _post_activate(self)
    cdef _activate(self)



cdef class BlockingSniffer(Sniffer):
    cdef unsigned char* python_callback_ptr
    cdef object python_callback
    cdef readonly PthreadWrap parent_thread

    cpdef sniff_and_store(self, container, f=?, int signal_mask=?)
    cpdef sniff_callback(self, f, int signal_mask=?)
    cdef void set_signal_mask(self) nogil
    cpdef ask_stop(self)


cdef class NonBlockingSniffer(Sniffer):
    cdef bool _nonblocking_mode
    cdef unsigned char* python_callback_ptr
    cdef object python_callback
    cdef object loop
    cdef bytes loop_type
    cdef object descriptor
    cdef object container
    cdef object old_status
    cpdef sniff_callback(self, callback)
    cpdef sniff_and_store(self, container, f=?)
    cpdef set_loop(self, loop, loop_type=?)
    cpdef stop(self)

cdef pcap_t* current_pcap_handle

cdef void sig_handler(int signum) nogil

cdef thread_pcap_node* register_pcap_for_thread(pthread_t thread, pcap_t* handle)
cdef int unregister_pcap_for_thread(pthread_t thread)
cdef int thread_has_pcap(pthread_t thread) nogil
cdef thread_pcap_node* get_pcap_for_thread(pthread_t thread) nogil


cdef extern from "list.h" nogil:
    struct list_head:
        list_head *next
        list_head *prev
    void INIT_LIST_HEAD(list_head *l)
    void list_add(list_head *new, list_head *head)
    void list_add_tail(list_head *new, list_head *head)
    void list_del(list_head *entry)
    void list_replace(list_head *old, list_head *new)
    int list_is_last(const list_head *l, const list_head *head)
    int list_empty(const list_head *head)
    int list_is_singular(const list_head *head)


ctypedef struct packet_node:
    list_head link
    long tv_sec
    int tv_usec
    int caplen
    int length
    unsigned char* buf

ctypedef struct thread_pcap_node:
    list_head link
    pthread_t thread
    int asked_to_stop
    pcap_t* handle

cdef list_head thread_pcap_global_list

cpdef object PcapExceptionFactory(int return_code, bytes error_msg=?, default=?)

