
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
    cdef int unregister(self)

    @staticmethod
    cdef inline thread_pcap_node* get_pcap_for_thread(pthread_t thread) nogil:
        global thread_pcap_global_list
        cdef list_head* cursor = thread_pcap_global_list.next
        cdef thread_pcap_node* node
        while cursor != &thread_pcap_global_list:
            node = <thread_pcap_node*>( <char *>cursor - <unsigned long> (&(<thread_pcap_node*>0).link) )
            if pthread_equal(node.thread, thread):
                return node
            cursor = cursor.next
        return NULL

    @staticmethod
    cdef inline thread_pcap_node* register_pcap_for_thread(pcap_t* handle) nogil:
        global lock, thread_pcap_global_list

        cdef thread_pcap_node* node
        cdef pthread_t thread = pthread_self()
        if BlockingSniffer.thread_has_pcap(thread) == 1:
            # todo: muf
            return NULL

        if pthread_mutex_lock(lock) != 0:
            # todo: muf
            return NULL

        node = <thread_pcap_node*> malloc(sizeof(thread_pcap_node))
        node.thread = thread
        node.handle = handle
        node.asked_to_stop = 0
        list_add_tail(&node.link, &thread_pcap_global_list)

        pthread_mutex_unlock(lock)
        return node

    @staticmethod
    cdef inline int unregister_pcap_for_thread() nogil:
        global lock, thread_pcap_global_list
        cdef list_head* cursor
        cdef list_head* nextnext
        cdef thread_pcap_node* node
        cdef pthread_t thread = pthread_self()
        if BlockingSniffer.thread_has_pcap(thread) == 0:
            # todo: muf
            return -1

        if pthread_mutex_lock(lock) != 0:
            # todo: muf
            return -1

        cursor = thread_pcap_global_list.next
        nextnext = cursor.next
        while cursor != &thread_pcap_global_list:
            node = <thread_pcap_node*>( <char *>cursor - <unsigned long> (&(<thread_pcap_node*>0).link) )
            if pthread_equal(node.thread, thread):
                list_del(&node.link)
                free(node)
                break
            cursor = nextnext
            nextnext = cursor.next

        pthread_mutex_unlock(lock)
        return 0

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

