# -*- coding: utf-8 -*-

cdef enum:
    PCAP_ERRBUF_SIZE = 256

cdef extern from "pcap/bpf.h":
    struct bpf_insn:
        unsigned short code;
        unsigned char jt;
        unsigned char jf;
        unsigned int k;
    struct bpf_program:
        unsigned int bf_len
        bpf_insn* bf_insns
    enum:
        DLT_NULL, DLT_EN10MB, DLT_EN3MB, DLT_AX25, DLT_PRONET, DLT_CHAOS, DLT_IEEE802, DLT_ARCNET, DLT_SLIP, DLT_PPP,
        DLT_FDDI, DLT_RAW, DLT_IEEE802_11, DLT_LOOP, DLT_ENC, DLT_PRISM_HEADER, DLT_AIRONET_HEADER, DLT_IEEE802_11_RADIO,
        DLT_IEEE802_11_RADIO_AVS, DLT_IPV4, DLT_IPV6

cdef extern from "pcap/pcap.h":
    ctypedef struct pcap_t
    ctypedef struct pcap_dumper_t

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

    ctypedef enum pcap_direction_t:
        PCAP_D_INOUT,
        PCAP_D_IN,
        PCAP_D_OUT

    enum:
        PCAP_WARNING, PCAP_WARNING_PROMISC_NOTSUP, PCAP_WARNING_TSTAMP_TYPE_NOTSUP

        PCAP_ERROR, PCAP_ERROR_BREAK, PCAP_ERROR_NOT_ACTIVATED, PCAP_ERROR_ACTIVATED, PCAP_ERROR_NO_SUCH_DEVICE
        PCAP_ERROR_RFMON_NOTSUP, PCAP_ERROR_NOT_RFMON, PCAP_ERROR_PERM_DENIED, PCAP_ERROR_IFACE_NOT_UP
        PCAP_ERROR_CANTSET_TSTAMP_TYPE, PCAP_ERROR_PROMISC_PERM_DENIED, PCAP_ERROR_TSTAMP_PRECISION_NOTSUP

        AF_INET, AF_LINK, AF_INET6

        PCAP_IF_LOOPBACK, PCAP_IF_UP, PCAP_IF_RUNNING

        PCAP_TSTAMP_PRECISION_MICRO, PCAP_TSTAMP_PRECISION_NANO, PCAP_TSTAMP_HOST, PCAP_TSTAMP_HOST_LOWPREC
        PCAP_TSTAMP_HOST_HIPREC, PCAP_TSTAMP_ADAPTER, PCAP_TSTAMP_ADAPTER_UNSYNCED


ctypedef pcap_pkthdr pcap_pkthdr_t
ctypedef bpf_program bpf_program_t
# noinspection PyUnresolvedReferences
ctypedef void (*pcap_handler) (unsigned char*, const pcap_pkthdr_t*, const unsigned char*)


cdef extern from "pcap/pcap.h" nogil:
    pcap_t *pcap_create(const char*, char*)
    pcap_t *pcap_open_offline(const char *fname, char *errbuf)
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
    int pcap_offline_filter(const bpf_program *fp, const pcap_pkthdr *h, const unsigned char *pkt)

    pcap_t* pcap_open_dead(int linktype, int snaplen)
    pcap_dumper_t* pcap_dump_open(pcap_t* p, const char* fname)
    pcap_dumper_t* pcap_dump_fopen(pcap_t* p, FILE* fp)
    void pcap_dump(unsigned char* user, pcap_pkthdr* h, unsigned char* sp)
    void pcap_dump_close(pcap_dumper_t* p)
    int pcap_dump_flush(pcap_dumper_t *p)
