# -*- coding: utf-8 -*-

cdef void sig_handler(int signum) nogil
ctypedef void (*sighandler_t)(int s) nogil

cdef class BlockingSniffer(Sniffer):
    cdef unsigned char* python_callback_ptr
    cdef object python_callback
    cdef pthread_t* parent_thread
    cdef sighandler_t old_sigint

    cpdef sniff_and_store(self, container, f=?, int set_signal_mask=?, int max_p=?)
    cpdef sniff_callback(self, f, int set_signal_mask=?, int max_p=?)
    cpdef ask_stop(self)

    cdef void _set_signal_mask(self) nogil
    cdef thread_pcap_node* register(self) except NULL
    cdef unregister(self)

    @staticmethod
    cdef thread_pcap_node* get_pcap_for_thread(pthread_t thread) nogil

    @staticmethod
    cdef thread_pcap_node* register_pcap_for_thread(pcap_t* handle) except NULL

    @staticmethod
    cdef unregister_pcap_for_thread()

    @staticmethod
    cdef inline int thread_has_pcap(pthread_t thread) nogil:
        return <int>(BlockingSniffer.get_pcap_for_thread(thread) != NULL)

    @staticmethod
    cdef inline void store_packet_node_in_seq_with_f(packet_node* n, object l, object f):
        obj = None
        try:
            obj = f(make_mview_from_const_uchar_buf(n.buf, n.caplen))
        except LibtinsException as ex:
            logger.debug('Ignored LibtinsException: %s', str(ex))
        except Exception as ex:
            logger.exception('store_packet_node_in_seq_with_f: an unexpected exception happened in f')
        else:
            if obj is not None:
                if isinstance(l, list):
                    (<list> l).append((n.tv_sec, n.tv_usec, n.length, obj))
                elif hasattr(l, 'append'):
                    l.append((n.tv_sec, n.tv_usec, n.length, obj))
                elif hasattr(l, 'put_nowait'):
                    l.put_nowait((n.tv_sec, n.tv_usec, n.length, obj))


    @staticmethod
    cdef inline void store_packet_node_in_seq(packet_node* n, object l, object f):
        if isinstance(l, list):
            (<list> l).append((n.tv_sec, n.tv_usec, n.length, <bytes>(n.buf[:n.caplen])))
        elif hasattr(l, 'append'):
            l.append((n.tv_sec, n.tv_usec, n.length, <bytes>(n.buf[:n.caplen])))
        elif hasattr(l, 'put_nowait'):
            l.put_nowait((n.tv_sec, n.tv_usec, n.length, <bytes>(n.buf[:n.caplen])))

