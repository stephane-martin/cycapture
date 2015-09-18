
cdef void sig_handler(int signum) nogil:
    cdef thread_pcap_node* current = BlockingSniffer.get_pcap_for_thread(pthread_self())
    if current != NULL:
        current.asked_to_stop = 1
        pcap_breakloop(current.handle)


# noinspection PyAttributeOutsideInit,PyGlobalUndefined
cdef class BlockingSniffer(Sniffer):
    active_sniffers = {}

    def __cinit__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                  monitor_mode=False, direction=PCAP_D_INOUT):
        if source is None:
            self.source = None
            self._handle = NULL
            return
        source = bytes(source)
        if len(source) == 0:
            self.source = None
            self._handle = NULL
            return
        self.source = source
        self._handle = pcap_create(<char*> source, self._errbuf)
        self.parent_thread = NULL

    def __init__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                  monitor_mode=False, direction=PCAP_D_INOUT):
        Sniffer.__init__(self,source, read_timeout, buffer_size, snapshot_length, promisc_mode, monitor_mode, direction)

    def __dealloc__(self):
        self.close()

    @classmethod
    def stop_all(cls):
        [s.ask_stop() for s in cls.active_sniffers.values()]


    cpdef ask_stop(self):
        if self.parent_thread != NULL:
            if pthread_kill(self.parent_thread[0], SIGUSR1) != 0:
                raise RuntimeError("BlockingSniffer.stop (sending SIGUSR1) failed")

    cdef void _set_signal_mask(self) nogil:
        cdef sigset_t s
        sigfillset(&s)
        pthread_sigmask(SIG_BLOCK, &s, NULL)
        sigemptyset(&s)
        sigaddset(&s, SIGUSR1)
        pthread_sigmask(SIG_UNBLOCK, &s, NULL)

    cdef thread_pcap_node* register(self) except NULL:
        if self in self.active_sniffers.values():
            raise RuntimeError("This BlockingSniffer is already actively listening")
        if BlockingSniffer.thread_has_pcap(pthread_self()) == 1:
            raise RuntimeError("only one sniffing action per thread is allowed")
        cdef thread_pcap_node* n = BlockingSniffer.register_pcap_for_thread(self._handle)
        if n == NULL:
            raise RuntimeError('register_pcap_for_thread failed')
        self.parent_thread = copy_pthread_self()
        self.active_sniffers[pthread_self_as_bytes()] = self
        cdef sighandler_t h = <sighandler_t> sig_handler
        self.old_sigint = libc_signal(SIGUSR1, h)
        siginterrupt(SIGUSR1, 1)
        return n

    cdef int unregister(self):
        libc_signal(SIGUSR1, self.old_sigint)
        siginterrupt(SIGUSR1, 1)
        cdef int res = BlockingSniffer.unregister_pcap_for_thread()
        cdef bytes ident = pthread_self_as_bytes()
        if ident in self.active_sniffers:
            del self.active_sniffers[ident]
        if self.parent_thread != NULL:
            free(self.parent_thread)
            self.parent_thread = NULL
        return res

    def sniff_and_export(self, fname_or_file_object, int max_p=-1):
        w = PacketWriter(self.datalink[0], fname_or_file_object)

        def _callback(sec, usec, caplen, length, mview):
            w.write(mview, sec, usec)

        self.sniff_callback(_callback, max_p=max_p)


    cpdef sniff_callback(self, f, int set_signal_mask=1, int max_p=-1):
        global sig_handler
        cdef int counted

        cdef char* error_msg = NULL
        cdef char* error_msg_source = NULL
        cdef thread_pcap_node* node
        # keep a reference to the callback... just in case...
        self.python_callback = f
        self.python_callback_ptr = <unsigned char *> (<void*> self.python_callback)

        if set_signal_mask:
            self._set_signal_mask()

        self.total = 0
        self.max_p = max_p
        with self._activate_if_needed():
            node = self.register()
            try:
                # the nogil here is important: without it, the other python threads may not be able to run
                with nogil:
                    while node.asked_to_stop == 0:
                        counted = pcap_dispatch(self._handle, 0, _do_python_callback, self.python_callback_ptr)
                        if counted == -2:
                            # pcap_breakloop was called
                            node.asked_to_stop = 1
                            break
                        elif counted < 0:
                            error_msg_source = pcap_geterr(self._handle)
                            error_msg = <char *> malloc(strlen(error_msg_source) + 1)
                            if error_msg != NULL:
                                strcpy(error_msg, error_msg_source)
                            node.asked_to_stop = 1
                            break
                        else:
                            self.total += counted

                        if 0 < self.max_p <= self.total:
                            node.asked_to_stop = 1
                            break

            finally:
                self.unregister()

        if error_msg != NULL:
            msg = bytes(error_msg)
            free(error_msg)
            raise PcapExceptionFactory(counted, msg, default=SniffingError)

    cpdef sniff_and_store(self, container, f=None, int set_signal_mask=1, int max_p=-1):
        global _store_c_callback, sig_handler
        cdef int counted
        cdef sighandler_t h = <sighandler_t> sig_handler
        cdef sighandler_t old_sigint
        cdef bytes error_message = b''
        cdef thread_pcap_node* node

        cdef dispatch_user_param usr
        cdef list_head head
        cdef list_head* cursor
        cdef list_head* nextnext
        cdef packet_node* pkt_node

        usr.fun = _store_c_callback

        cdef store_fun store
        if f is None:
            store = BlockingSniffer.store_packet_node_in_seq
        else:
            store = BlockingSniffer.store_packet_node_in_seq_with_f


        if set_signal_mask:
            self._set_signal_mask()

        self.total = 0
        self.max_p = max_p

        with self._activate_if_needed():
            node = self.register()

            try:
                while node.asked_to_stop == 0:
                    with nogil:
                        INIT_LIST_HEAD(&head)
                        usr.param = <void*>&head
                        counted = pcap_dispatch(self._handle, 0, _do_c_callback, <unsigned char*> &usr)

                    cursor = head.next
                    nextnext = cursor.next
                    while cursor != &head:
                        pkt_node = <packet_node*>( <char *>cursor - <unsigned long> (&(<packet_node*>0).link) )
                        store(pkt_node, container, f)
                        free(pkt_node.buf)
                        list_del(&pkt_node.link)
                        free(pkt_node)
                        cursor = nextnext
                        nextnext = cursor.next

                    if counted == -2:
                        # pcap_breakloop was called
                        node.asked_to_stop = 1
                        break
                    elif counted < 0:
                        error_message = <bytes> (pcap_geterr(self._handle))
                        node.asked_to_stop = 1
                        break
                    else:
                        self.total += counted

                    if 0 < self.max_p <= self.total:
                        node.asked_to_stop = 1
                        break

            finally:
                self.unregister()

        if error_message:
            raise PcapExceptionFactory(counted, bytes(error_message), default=SniffingError)
