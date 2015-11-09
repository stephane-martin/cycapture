# -*- coding: utf-8 -*-

cdef void sigaction_handler(int signum, siginfo_t* info, void* unused) nogil:
    registry_pcap_set_stopping()


cdef class BlockingSniffer(BaseSniffer):
    """
    The blocking sniffer captures packets from an interface, in a blocking way: its `sniff_something` methods do not
    return and block the current thread.

    So `BlockingSniffer` is typically used in a multi-threaded application. In fact, each `BlockingSniffer` instance must
    listen in a different thread.

    The ``ask_stop`` method is thread safe and can be called from any thread.
    """
    active_sniffers = {}

    def __cinit__(self, interface=None, filename=None, int read_timeout=5000, int buffer_size=0, int snapshot_length=2000,
                  promisc_mode=False, monitor_mode=False, direction=PCAP_D_INOUT):
        pass

    def __init__(self, interface=None, filename=None, int read_timeout=5000, int buffer_size=0, int snapshot_length=2000,
                 promisc_mode=False, monitor_mode=False, direction=PCAP_D_INOUT):
        """
        __init__(interface=None, filename=None, int read_timeout=5000, int buffer_size=0, int snapshot_length=2000, promisc_mode=False, monitor_mode=False, direction=PCAP_D_INOUT)

        Parameters
        ----------
        interface: bytes
            which interface to sniff on
        filename: file or bytes
            which file to get the packets from
        read_timeout: int
            if read_timeout > 0, wait at most read_timeout mseconds to (batch-) deliver the captured packets
        buffer_size: int
            platform buffer size for captured packets. 0 means 'use system default'.
        snapshot_length: int
            only the first snaplen_length bytes of each packet will be captured and provided as packet data
        promisc_mode: bool
            a mode in which all packets, even if they are not sent to an address that the adapter recognizes, are provided
        monitor_mode: bool
            in monitor mode ("Radio Frequency MONitor"), the interface will supply all frames that it receives, with
            802.11 headers.
        direction: :py:class:`~.DIRECTION`
            set direction to capture only  packets received by the machine or only packets sent by the machine
        """
        BaseSniffer.__init__(self, interface, filename, read_timeout, buffer_size, snapshot_length, promisc_mode, monitor_mode, direction)
        self.python_callback = None
        self.python_callback_ptr = NULL
        self.parent_thread = None
        self.total = 0
        self.max_p = -1
        self.old_sigaction = None

    def __dealloc__(self):
        if self in BlockingSniffer.active_sniffers.values():
            self.ask_stop()
            while self in BlockingSniffer.active_sniffers.values():
                sleep(1)
        self.close()

    @classmethod
    def stop_all(cls):
        """
        Ask all currently running sniffers to stop. Can be called from any thread.
        """
        [s.ask_stop() for s in cls.active_sniffers.values()]

    cpdef ask_stop(self):
        """
        ask_stop()
        Ask the current running sniffer to stop. Can be called from any thread.
        """
        if self.parent_thread is not None:
            if self.parent_thread.kill(SIGUSR1) != 0:
                raise RuntimeError("BlockingSniffer.stop (sending SIGUSR1) failed")

    def sniff_and_export(self, fname_or_file_object, int max_p=-1):
        """
        Sniff and write the captured packets to a file.

        Parameters
        ----------
        fname_or_file_object: file or bytes
            output file
        max_p: int
            how many packets to capture (-1 for unlimited)
        """
        with PacketWriter(self.datalink[0], fname_or_file_object) as w:

            def _callback(sec, usec, caplen, length, mview):
                w.write(mview, sec, usec)

            self.sniff_callback(_callback, max_p=max_p)

    def iterator(self, f=None, int max_p=-1, int cache_size=10000):
        """
        iterator(f=None, int max_p=-1, int cache_size=10000)
        Provides an iterator that returns captured packets.

        Parameters
        ----------
        f: function
            optional transformation for the captured packets
        max_p: int
            minimum number of packets that should be captured
        cache_size: int
            size of the internal queue

        Returns
        -------
        iterator: :py:class:`~.SniffingIterator`


        The iterator starts a background thread to capture the packets (using the sniff methods). So the iterator
        should be used with a context manager to ensure proper initialization and garbage of the thread.

        The background thread stores the packets in an internal queue. When ``next()`` is called on the iterator,
        a packet is poped from the internal queue. The max queue size can be specified with the cache_size parameter
        (cache_size = 0 means an infinite queue). The queue has deque semantics when full.

        The iterator gives packets in format::

            (timestamp, timestamp_ms_part, packet_length, packet_as_bytes)

        Optionally, the captured packet may be transformed by a function f, before being stored in the internal queue.
        The f function should accept one argument: the captured packet as a memoryview. If a function f is given, the
        iterator gives packets in format::

            (timestamp, timestamp_ms_part, packet_length, f(memoryview))

        Any LibtinsException that may happened in f will be caught and logged at debug level. Any other exception will
        be caught and logged at exception level.

        Depending on the sniffer snapshot_length property, the captured packet might be smaller than packet_length.

        Example
        -------

            >>> from cycapture.libpcap import BlockingSniffer
            >>> from cycapture.libtins import EthernetII
            >>> sniffer = BlockingSniffer(interface="eth0", snapshot_length=65000)
            >>> with sniffer.iterator(max_p=1000) as i:     # capture roughly 1000 packets
            ...     for ts, ts_ms, length, packet in i:
            ...         print('captured one packet')
            >>> # when we exit the with statement, the backgroung sniffing thread is stopped
            >>> f = lambda mview: EthernetII.from_buffer(mview)
            >>> with sniffer.iterator(max_p=1000, f=f) as i:        # parse the packets using libtins
            ...     for ts, ts_ms, length, ethernet_pdu in i:
            ...         print("got one pdu")
        """
        return SniffingIterator(self, f, max_p, cache_size)

    cpdef sniff_callback(self, f, int set_signal_mask=1, int max_p=-1):
        """
        sniff_callback(f, int set_signal_mask=1, int max_p=-1)
        Start to sniff packets and call a given callback for each packet.

        Parameters
        ----------
        f: function
            callback function
        set_signal_mask: bool
            should a signal mask be applied on the listening thread to block unwanted signals
        max_p: int
            minimum number of packets to sniff. -1 for unlimited.


        The callback function must accept 4 arguments like::

            (timestamp, ms_timestamp, packet_length, packet_as_memoryview)

        The provided memoryview is only valid in the context of the callback call, so you should copy its content if
        you'd like to store it (eg with ``memoryview.tobytes`` method).

        Any LibtinsException happening in f will be caught and logged as debug. Any other exception will be caught and
        logged as exception.

        Example
        -------

            >>> from cycapture.libpcap import BlockingSniffer
            >>> sniffer = BlockingSniffer(interface="eth0", snapshot_length=65000)
            >>> def callback(ts, ms_ts, length, mview):
            ...     print('callback!')
            >>> sniffer.sniff_callback(f=callback, max_p=1000)
        """
        # todo: check that the callback has the right signature
        cdef int counted = 0

        cdef char* error_msg = NULL
        cdef char* error_msg_source = NULL
        cdef thread_pcap_node* node
        # keep a reference to the callback so that the python_callback_ptr stays valid
        self.python_callback = f
        self.python_callback_ptr = <unsigned char *> (<void*> self.python_callback)

        if set_signal_mask:
            block_sig_except(SIGUSR1)

        self.total = 0
        self.max_p = max_p
        with self.activate_if_needed():
            self.register()
            try:
                # the nogil here is important: without it, the other python threads may not be able to run
                with nogil:
                    while registry_pcap_has_stopping() == 0:
                        counted = pcap_dispatch(self._handle, 0, _do_python_callback, self.python_callback_ptr)
                        if counted == -2:
                            # pcap_breakloop was called
                            registry_pcap_set_stopping()
                            break
                        elif counted < 0:
                            error_msg_source = pcap_geterr(self._handle)
                            error_msg = <char *> malloc(strlen(error_msg_source) + 1)
                            if error_msg != NULL:
                                strcpy(error_msg, error_msg_source)
                            registry_pcap_set_stopping()
                            break
                        else:
                            self.total += counted

                        if 0 < self.max_p <= self.total:
                            registry_pcap_set_stopping()
                            break

            finally:
                self.unregister()

        if error_msg != NULL:
            msg = bytes(error_msg)
            free(error_msg)
            raise PcapExceptionFactory(counted, msg, default=SniffingError)

    cpdef sniff_and_store(self, container, f=None, int set_signal_mask=1, int max_p=-1):
        """
        sniff_and_store(container, f=None, int set_signal_mask=1, int max_p=-1)
        Start sniffing and store the packets in a container object.

        Parameters
        ----------
        container: object
            a python container, such as a deque, that supports method ``append`` or ``put_nowait``
        f: function or None
            if provided, the function `f` will be applied to each capture packet before it is stored
        set_signal_mask: bool
            should a signal mask be applied on the listening thread to block unwanted signals
        max_p: int
            minimum number of packets to capture. -1 for unlimited.


        The `container` should support an ``append`` or ``put_nowait`` method. This method should be thread-safe, so that you
        can pop elements from the container in another thread. collections.deque or queue.Queue fit well.

        The optional function f, if given, will be applied to each captured packet before being put in the container. f
        should accept one argument: the captured packet as a memoryview.

        Any LibtinsException happening in f will be caught and logged as debug. Any other exception will be caught and
        logged as exception.

        Example
        -------

            >>> from cycapture.libpcap import BlockingSniffer
            >>> from cycapture.libtins import EthernetII
            >>> from collections import deque
            >>> q = deque()
            >>> sniffer = BlockingSniffer(interface="eth0", snapshot_length=65000)
            >>> f = lambda mview: EthernetII.from_buffer(mview)
            >>> sniffer.sniff_and_store(container=q, f=f, max_p=1000)
            >>> print(len(q))
        """
        cdef int counted = 0
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
            block_sig_except(SIGUSR1)

        self.total = 0
        self.max_p = max_p

        with self.activate_if_needed():
            self.register()

            try:
                while registry_pcap_has_stopping() == 0:
                    with nogil:
                        INIT_LIST_HEAD(&head)
                        usr.param = <void*>&head
                        counted = pcap_dispatch(self._handle, 0, _do_c_callback, <unsigned char*> &usr)

                    cursor = head.next
                    nextnext = cursor.next
                    while cursor != &head:
                        pkt_node = <packet_node*>( <char *>cursor - <unsigned long> (&(<packet_node*>0).link) )
                        store(pkt_node, container, f)           # python code... need the GIL
                        free(pkt_node.buf)
                        list_del(&pkt_node.link)
                        free(pkt_node)
                        cursor = nextnext
                        nextnext = cursor.next

                    if counted == -2:
                        # pcap_breakloop was called
                        registry_pcap_set_stopping()
                        break
                    elif counted < 0:
                        error_message = <bytes> (pcap_geterr(self._handle))
                        registry_pcap_set_stopping()
                        break
                    else:
                        self.total += counted

                    if 0 < self.max_p <= self.total:
                        registry_pcap_set_stopping()
                        break

            finally:
                self.unregister()

        if error_message:
            raise PcapExceptionFactory(counted, bytes(error_message), default=SniffingError)


    cdef register(self):
        if self._handle is NULL:
            raise RuntimeError(u"register: no valid pcap handle")
        if self in BlockingSniffer.active_sniffers.values():
            raise RuntimeError(u"register: this BlockingSniffer is already actively listening")
        if registry_pcap_has():
            raise RuntimeError(u"register: only one sniffing action per thread is allowed")

        registry_pcap_set(self._handle)    # can raise exc too
        self.parent_thread = PThread()
        self.active_sniffers[pthread_hash()] = self

        # set signal handler
        cdef Sigaction new_sigaction = Sigaction()
        new_sigaction.set_sigaction_handler(sigaction_handler)
        self.old_sigaction = new_sigaction.set_for_signum(SIGUSR1)
        set_sig_interrupt(SIGUSR1)

    cdef unregister(self):
        # unset signal handler
        if self.old_sigaction is not None:
            self.old_sigaction.set_for_signum(SIGUSR1)
            self.old_sigaction = None
            set_sig_interrupt(SIGUSR1)

        registry_pcap_unset()        # can raise exc
        cdef uint32_t ident = pthread_hash()
        if ident in self.active_sniffers:
            del self.active_sniffers[ident]
        self.parent_thread = None






