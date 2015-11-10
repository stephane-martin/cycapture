# -*- coding: utf-8 -*-

cdef class SniffingIterator(object):
    """
    Helper iterator to get packets from a BlockingSniffer. To be used as a context manager.
    """

    def __init__(self, BlockingSniffer sniffer, f=None, int max_p=-1, int cache_size=10000):
        if sniffer is None:
            raise TypeError('sniffer must be a BlockingSniffer object')
        self.sniffer = sniffer
        self.max_p = int(max_p)
        self.total_returned = 0
        self.cache_size = int(cache_size)
        self.f = f
        self.queue = deque() if self.cache_size <= 0 else deque([], self.cache_size)
        self.total_returned = 0
        self.thread = threading.Thread(target=self._background_sniff)

    def __enter__(self):
        """
        __enter__()
        """
        self.start()
        return self

    def __exit__(self, t, value, traceback):
        """
        __exit__(t, value, traceback)
        """
        self.stop()

    cpdef start(self):
        """
        start()
        Start the background sniffing thread that feeds the iterator.
        """
        if not self.thread.is_alive():
            if self.sniffer in BlockingSniffer.active_sniffers.values():
                raise RuntimeError('sniffer is already actively listening')
            self.thread.start()

    cpdef stop(self):
        """
        stop()
        Stop the background thread.
        """
        if self.thread.is_alive():
            if self.sniffer in BlockingSniffer.active_sniffers.values():
                self.sniffer.ask_stop()
            self.thread.join()      # wait that the background thread actually stops


    def _background_sniff(self):
        # let's start to sniff and store the results in queue
        # (we ask the sniffer to return just as many packets as we need)
        self.sniffer.sniff_and_store(self.queue, f=self.f, max_p=self.max_p-len(self.queue))

    def __iter__(self):
        """
        __iter__()
        """
        return self

    def __next__(self):
        if 0 < self.max_p <= self.total_returned:
            # we already returned enough packets
            raise StopIteration
        if self.queue:
            self.total_returned += 1
            return self.queue.popleft()
        while self.thread.is_alive():
            # wait that something is appended into the queue
            with nogil:
                csleep(1)
            if self.queue:
                self.total_returned += 1
                return self.queue.popleft()
        if self.queue:
            self.total_returned += 1
            return self.queue.popleft()
        # the sniffer thread is not active and we don't have any available packet
        raise StopIteration

