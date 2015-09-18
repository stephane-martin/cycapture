
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


cdef inline void _store_c_callback(long tv_sec, int tv_usec, int caplen, int length, const unsigned char* pkt, void* p) nogil:
    cdef packet_node* temp = <packet_node*> malloc(sizeof(packet_node))
    temp.tv_sec = tv_sec
    temp.tv_usec = tv_usec
    temp.caplen = caplen
    temp.length = length
    temp.buf = <unsigned char*> malloc(caplen)
    memcpy(<void*> temp.buf, <void*>pkt, caplen)
    list_add_tail(&temp.link, <list_head*> p)


cdef inline void _do_c_callback(unsigned char* usr, const pcap_pkthdr_t* pkthdr, const unsigned char* pkt) nogil:
    cdef dispatch_user_param* s = <dispatch_user_param*> usr
    (s.fun)(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.caplen, pkthdr.len, pkt, s.param)


cdef inline void _do_python_callback(unsigned char* usr, const pcap_pkthdr_t* pkthdr, const unsigned char* pkt) with gil:
    try:
        (<object> (<void*> usr))(
            pkthdr.ts.tv_sec,
            pkthdr.ts.tv_usec,
            pkthdr.caplen,
            pkthdr.len,
            make_mview_from_const_uchar_buf(pkt, pkthdr.caplen)
        )
    except LibtinsException as ex:
        logger.debug('Ignored LibtinsException: %s', str(ex))
    except Exception as ex:
        logger.exception('_do_python_callback: an unexpected exception happened')


ctypedef void (*store_fun) (packet_node* n, object l, object f)

ctypedef void (*c_callback) (long tv_sec, int tv_usec, int caplen, int length, const unsigned char* pkt, void* p) nogil

ctypedef struct dispatch_user_param:
    c_callback fun
    void* param


