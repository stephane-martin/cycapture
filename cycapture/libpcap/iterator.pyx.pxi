# -*- coding: utf-8 -*-


cdef class SniffingIterator(object):

    def __init__(self, BlockingSniffer sniffer, f=None, int max_p=-1, int cache_size=10000):
        if sniffer is None:
            raise TypeError('sniffer must be a BlockingSniffer object')
        if sniffer in BlockingSniffer.active_sniffers.values():
            raise RuntimeError('sniffer is already actively listening')
        self.sniffer = sniffer
        self.queue = deque() if cache_size <= 0 else deque([], cache_size)
        self.max_p = int(max_p)
        self.total_returned = 0
        self.cache_size = int(cache_size)
        self.f = f

        self.thread = threading.Thread(target=self._background_sniff)
        self.thread.start()

    def __iter__(self):
        return self

    def __next__(self):
        if self.queue is None:
            # the iterator is closed
            raise StopIteration
        if 0 < self.max_p <= self.total_returned:
            # we already returned enough packets
            self.queue = None     # try to free memory...
            raise StopIteration
        if self.queue:
            self.total_returned += 1
            return self.queue.popleft()
        while self.thread.isAlive():
            # wait that something is appended into the queue
            sleep(1)
            if self.queue:
                self.total_returned += 1
                return self.queue.popleft()
        if self.queue:
            self.total_returned += 1
            return self.queue.popleft()
        # the sniffer is not anymore active and we don't have any available packet
        self.queue = None     # try to free memory...
        raise StopIteration

    def _background_sniff(self):
        # let's start to sniff and store the results in queue
        self.sniffer.sniff_and_store(self.queue, f=self.f, max_p=self.max_p)

    def stop(self):
        if self.sniffer in BlockingSniffer.active_sniffers.values():
            self.sniffer.ask_stop()

    def next(self):
        return self.__next__()
