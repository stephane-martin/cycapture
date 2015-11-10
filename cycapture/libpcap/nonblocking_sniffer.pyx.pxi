# -*- coding: utf-8 -*-

cdef class AsyncHandlerCallback(object):
    def __cinit__(self, NonBlockingSniffer sniffer, callback):
        self.callback = callback
        self.ptr = <unsigned char*> (<void*> self.callback)
        self.sniffer = sniffer

    def __init__(self, NonBlockingSniffer sniffer, callback):
        pass

    def __call__(self, fd=None, events=None):
        cdef int counted = 1
        while counted > 0:
            counted = pcap_dispatch(self.sniffer._handle, 0, _do_python_callback, self.ptr)
            if counted >= 0:
                self.sniffer.total += counted
        if 0 < self.sniffer.max_p <= self.sniffer.total:
            self.sniffer.stop()

cdef class AsyncHandlerStore(object):
    def __cinit__(self, NonBlockingSniffer sniffer, container, f):

        if f is None:
            if isinstance(container, list):
                def _cllbck(sec, usec, caplen, length, mview):
                    (<list> container).append((sec, usec, length, mview.tobytes()))
            elif hasattr(container, 'append'):
                def _cllbck(sec, usec, caplen, length, mview):
                    container.append((sec, usec, length, mview.tobytes()))
            elif hasattr(container, 'put_nowait'):
                def _cllbck(sec, usec, caplen, length, mview):
                    container.put_nowait((sec, usec, length, mview.tobytes()))
            else:
                def _cllbck(sec, usec, caplen, length, mview):
                    pass

        else:
            if isinstance(container, list):
                def _cllbck(sec, usec, caplen, length, mview):
                    obj = f(mview)
                    # if an exception happens in f, it will be caught in _do_python_callback
                    if obj is not None:
                        (<list> container).append((sec, usec, length, f(mview)))
            elif hasattr(container, 'append'):
                def _cllbck(sec, usec, caplen, length, mview):
                    obj = f(mview)
                    # if an exception happens in f, it will be caught in _do_python_callback
                    if obj is not None:
                        container.append((sec, usec, length, f(mview)))
            elif hasattr(container, 'put_nowait'):
                def _cllbck(sec, usec, caplen, length, mview):
                    obj = f(mview)
                    # if an exception happens in f, it will be caught in _do_python_callback
                    if obj is not None:
                        container.put_nowait((sec, usec, length, f(mview)))
            else:
                # ???
                def _cllbck(sec, usec, caplen, length, mview):
                    f(mview)

        self.callback = _cllbck
        self.ptr = <unsigned char*> (<void*> self.callback)
        self.sniffer = sniffer

    def __init__(self, NonBlockingSniffer sniffer, container, f):
        pass

    def __call__(self, fd=None, events=None):
        cdef int counted = 1
        while counted > 0:
            counted = pcap_dispatch(self.sniffer._handle, 0, _do_python_callback, self.ptr)
            if counted >= 0:
                self.sniffer.total += counted
        if 0 < self.sniffer.max_p <= self.sniffer.total:
            self.sniffer.stop()


cdef class NonBlockingSniffer(BaseSniffer):
    """
    Provide a non-blocking sniffer, that's supposed to work with an async ioloop.

    * First, construct the sniffer object as usual.
    * Then, set the ioloop you want to use with the ``NonBlockingSniffer.set_loop`` method.
    * Finally, use one of the `sniff_something` methods to start capturing packets.

    The io loop will monitor the sniffer, and it will trigger the appropriate actions when some packets will be actually
    available.

    If you use the ``NonBlockingSniffer.sniff_callback`` method, make sure that your provided callback does not block
    the ioloop.
    """
    active_sniffers = {}

    def __cinit__(self, interface=None, filename=None, int read_timeout=5000, int buffer_size=0, int snapshot_length=2000,
                  promisc_mode=False, monitor_mode=False, direction=BaseSniffer.DIRECTION.PCAP_D_INOUT):
        pass

    def __dealloc__(self):
        self.close()

    def __init__(self, interface=None, filename=None, int read_timeout=5000, int buffer_size=0, int snapshot_length=2000,
                  promisc_mode=False, monitor_mode=False, direction=BaseSniffer.DIRECTION.PCAP_D_INOUT):
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
            platform buffer size in bytes for captured packets. 0 means 'use system default'.
        snapshot_length: int
            only the first snaplen_length bytes of each packet will be captured and provided as packet data
        promisc_mode: bool
            a mode in which all packets, even if they are not sent to an address that the adapter recognizes, are provided
        monitor_mode: bool
            in monitor mode ("Radio Frequency MONitor"), the interface will supply all frames that it receives, with
            802.11 headers.
        direction: :py:class:`~.BaseSniffer.DIRECTION`
            set direction to capture only  packets received by the machine or only packets sent by the machine
        """
        BaseSniffer.__init__(self, interface, filename, read_timeout, buffer_size, snapshot_length, promisc_mode, monitor_mode, direction)
        self.loop = None
        self.loop_type = None
        self.descriptor = None
        self.writer = None

    cpdef set_loop(self, loop, loop_type="tornado"):
        """
        set_loop(loop, loop_type="tornado")
        Sets the ioloop to use with the current sniffer.

        Parameters
        ----------
        loop: ioloop to use
        loop_type: "tornado" or "asyncio"

        Returns
        -------
        self
        """
        self.loop = loop
        self.loop_type = bytes(loop_type).lower().strip()
        return self

    cdef object activate(self):
        BaseSniffer.activate(self)
        cdef int res = pcap_setnonblock(self._handle, 1, self._errbuf)
        if res < 0:
            raise PcapExceptionFactory(res, self._errbuf, default=SetNonblockingModeError)

    cpdef sniff_callback(self, callback, int max_p=-1):
        """
        sniff_callback(callback, int max_p=-1)
        Sniff and call some function for each captured packet.

        Parameters
        ----------
        callback: function
            this function will be called for each captured packet
        max_p: int
            minimum number of packets to capture (-1 means unlimited)

        Returns
        -------
        fd: int
            the file descriptor corresponding to the current sniffer


        The callback function must accept 4 parameters like::

            (timestamp, ms_timestamp, packet_length, packet_as_memoryview)

        The packet_as_memoryview will only be valid in context of callback.
        """
        if self in self.active_sniffers.values():
            raise RuntimeError("This NonBlockingSniffer is already actively listening")
        if self.loop is None or self.loop_type is None:
            raise RuntimeError("set loop and loop_type first")
        self.active_sniffers[id(self)] = self
        self.old_status = self.activated
        if not self.old_status:
            self.activate()

        self.descriptor = pcap_get_selectable_fd(self._handle)
        self.total = 0
        self.max_p = max_p
        if self.loop_type == "tornado":
            self.loop.add_handler(self.descriptor, AsyncHandlerCallback(self, callback), 1) # "1" is for READ events
        elif self.loop_type == "asyncio":
            self.loop.add_reader(self.descriptor, AsyncHandlerCallback(self, callback))
        return self.descriptor

    cpdef sniff_and_store(self, container, f=None, int max_p=-1):
        """
        sniff_and_store(container, f=None, int max_p=-1)
        Sniff and store the captured packet in some container.

        Parameters
        ----------
        container: object
            the container where to store the captured packets
        f: function
            an optional transformation of the captured packets
        max_p: int
            minimum number of packets to capture (-1 means unlimited)

        Returns
        -------
        fd: int
            the file descriptor corresponding to the current sniffer


        The container can be any kind of object that support `append` or `put_nowait`. Typically you can use
        ``tornado.queues.Queue`` objects. The container will be filled with objects like::

            (timestamp, ms_timestamp, packet_length, packet_as_bytes)

        The optional function f, if given, will be applied to each packet, so what's stored in the container
        becomes::

            (timestamp, ms_timestamp, packet_length, f(packet_as_memoryview))

        """
        if self in self.active_sniffers.values():
            raise RuntimeError("This NonBlockingSniffer is already actively listening")
        if self.loop is None or self.loop_type is None:
            raise RuntimeError("set loop and loop_type first")
        self.active_sniffers[id(self)] = self
        self.old_status = self.activated
        if not self.old_status:
            self.activate()

        self.descriptor = pcap_get_selectable_fd(self._handle)
        self.total = 0
        self.max_p = max_p
        if self.loop_type == "tornado":
            # "1" is for READ events
            self.loop.add_handler(self.descriptor, AsyncHandlerStore(self, container, f), 1)
        elif self.loop_type == "asyncio":
            self.loop.add_reader(self.descriptor, AsyncHandlerStore(self, container, f))
        return self.descriptor

    def sniff_and_export(self, fname_or_file_object, int max_p=-1):
        """
        Sniff and stores the captured packets in a pcap file.

        Parameters
        ----------
        fname_or_file_object: file or bytes
            pcap file
        max_p: int
            minimum number of packets to store (-1 means unlimited)

        Returns
        -------
        fd: int
            the file descriptor corresponding to the current sniffer
        """
        if self in self.active_sniffers.values():
            raise RuntimeError("This NonBlockingSniffer is already actively listening")
        w = NonBlockingPacketWriter(self.datalink[0], fname_or_file_object)
        w.open()    # starts the background IO thread

        def _callback(sec, usec, length, mview):
            w.write(mview, sec, usec)

        self.writer = w
        return self.sniff_callback(_callback, max_p=max_p)


    cpdef stop(self):
        """
        stop()
        Stop the sniffer.

        The stop method will:
        * remove the handlers from the ioloop (so no more callbacks will be called by the ioloop when some packets are
        available)
        * close the file writer, if one was being used
        * close the pcap handle
        """
        if self.descriptor is not None and self.loop is not None:
            if self.loop_type == "tornado":
                self.loop.remove_handler(self.descriptor)
            elif self.loop_type == "asyncio":
                self.loop.remove_reader(self.descriptor)
            self.descriptor = None
        if self.writer is not None:
            self.writer.close()     # stop the background IO thread
            self.writer = None
        if id(self) in self.active_sniffers:
            del self.active_sniffers[id(self)]
        if not self.old_status:
            self.close()

    @classmethod
    def stop_all(cls):
        """
        Stop all the non-blocking sniffers
        """
        for s in cls.active_sniffers.values():
            s.stop()
