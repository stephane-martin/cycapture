# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from .._pthreadwrap cimport create_error_check_lock, pthread_mutex_lock, pthread_mutex_unlock, destroy_error_check_lock
# noinspection PyUnresolvedReferences
from .._pthreadwrap cimport PThread

# noinspection PyUnresolvedReferences
from .._signal cimport block_sig_except, set_sig_interrupt, unset_sig_interrupt, set_sigaction
from .._signal cimport SIGUSR1
from .._signal cimport siginfo_t
from .._signal cimport Sigaction

cdef void sigaction_handler(int signum, siginfo_t* info, void* unused) nogil

cdef class BlockingSniffer(BaseSniffer):
    cdef unsigned char* python_callback_ptr
    cdef object python_callback
    cdef PThread parent_thread
    cdef Sigaction old_sigaction

    cpdef sniff_and_store(self, container, f=?, int set_signal_mask=?, int max_p=?)
    cpdef sniff_callback(self, f, int set_signal_mask=?, int max_p=?)
    cpdef ask_stop(self)

    cdef register(self)
    cdef unregister(self)

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

