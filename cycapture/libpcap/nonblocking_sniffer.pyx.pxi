


# noinspection PyAttributeOutsideInit
cdef class NonBlockingSniffer(Sniffer):
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

    def __dealloc__(self):
        self.close()

    def __init__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                 monitor_mode=False, direction=PCAP_D_INOUT):
        Sniffer.__init__(self, source, read_timeout, buffer_size, snapshot_length, promisc_mode, monitor_mode, direction)
        self.loop = None
        self.loop_type = None
        self.descriptor = None
        self.writer = None

    cpdef set_loop(self, loop, loop_type="tornado"):
        loop_type = bytes(loop_type).lower().strip()
        self.loop = loop
        self.loop_type = loop_type
        return self

    cdef object _activate(self):
        Sniffer._activate(self)
        cdef int res
        res = pcap_setnonblock(self._handle, 1, self._errbuf)
        if res < 0:
            raise PcapExceptionFactory(res, self._errbuf, default=SetNonblockingModeError)

    def _make_tornado_handler_callback(self, callback):
        def _tornado_handler_callback(fd=None, events=None):
            cdef unsigned char* ptr = <unsigned char*> (<void*> callback)
            cdef int counted = 1
            while counted > 0:
                counted = pcap_dispatch(self._handle, 0, _do_python_callback, ptr)
                self.total += counted
            if 0 < self.max_p <= self.total:
                self.stop()
        return _tornado_handler_callback

    def _make_tornado_handle_store(self, container, f):
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
                def _cllbck(sec, usec, caplen, length, mview):
                    f(mview)


        def _tornado_handler_store(fd=None, events=None):
            cdef unsigned char* ptr = <unsigned char*> (<void*> _cllbck)
            cdef int counted = 1
            while counted > 0:
                counted = pcap_dispatch(self._handle, 0, _do_python_callback, ptr)
                self.total += counted
            if 0 < self.max_p <= self.total:
                self.stop()
        return _tornado_handler_store


    cpdef sniff_callback(self, callback, int max_p=-1):
        if self in self.active_sniffers.values():
            raise RuntimeError("This NonBlockingSniffer is already actively listening")
        if self.loop is None or self.loop_type is None:
            raise RuntimeError("set loop and loop_type first")
        self.active_sniffers[id(self)] = self
        self.old_status = self.activated
        if not self.activated:
            self._activate()

        # keep a ref... so that callback can't be garbage collected
        self.python_callback = callback

        self.descriptor = pcap_get_selectable_fd(self._handle)
        self.total = 0
        self.max_p = max_p
        if self.loop_type == "tornado":
            # "1" is for READ events
            self.loop.add_handler(self.descriptor, self._make_tornado_handler_callback(callback), 1)
        elif self.loop_type == "asyncio":
            self.loop.add_reader(self.descriptor, self._make_tornado_handler_callback(callback))
        return self.descriptor

    cpdef sniff_and_store(self, container, f=None, int max_p=-1):
        if self in self.active_sniffers.values():
            raise RuntimeError("This NonBlockingSniffer is already actively listening")
        if self.loop is None or self.loop_type is None:
            raise RuntimeError("set loop and loop_type first")
        self.active_sniffers[id(self)] = self
        self.old_status = self.activated
        self.container = container
        if not self.activated:
            self._activate()

        # keep a ref... so that callback can't be garbage collected
        self.python_callback = f

        self.descriptor = pcap_get_selectable_fd(self._handle)
        self.total = 0
        self.max_p = max_p
        if self.loop_type == "tornado":
            # "1" is for READ events
            self.loop.add_handler(self.descriptor, self._make_tornado_handle_store(container, f), 1)
        elif self.loop_type == "asyncio":
            self.loop.add_reader(self.descriptor, self._make_tornado_handle_store(container, f))
        return self.descriptor

    def sniff_and_export(self, fname_or_file_object, int max_p=-1):
        if self in self.active_sniffers.values():
            raise RuntimeError("This NonBlockingSniffer is already actively listening")
        w = NonBlockingPacketWriter(self.datalink[0], fname_or_file_object)

        def _callback(sec, usec, caplen, length, mview):
            w.write(mview, sec, usec)

        self.writer = w
        self.sniff_callback(_callback, max_p=max_p)


    cpdef stop(self):
        if self.descriptor is not None and self.loop is not None:
            if self.loop_type == "tornado":
                self.loop.remove_handler(self.descriptor)
            elif self.loop_type == "asyncio":
                self.loop.remove_reader(self.descriptor)
            self.descriptor = None
        if self.writer is not None:
            self.writer.stop()
        if id(self) in self.active_sniffers:
            del self.active_sniffers[id(self)]
        if not self.old_status:
            self.close()

    @classmethod
    def stop_all(cls):
        for s in cls.active_sniffers.values():
            s.stop()
