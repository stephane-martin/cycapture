

cdef int _normalize_linktype(object linktype) except -1:
    if isinstance(linktype, DLT):
        linktype = linktype.value
    elif isinstance(linktype, PDU):
        if linktype.datalink_type == -1:
            raise TypeError("This kind of PDU doesn't have a clear datalink type")
        linktype = linktype.datalink_type
    elif isinstance(linktype, type) and hasattr(linktype, 'datalink_type'):
        if linktype.datalink_type == -1:
            raise TypeError("This kind of PDU doesn't have a clear datalink type")
        linktype = linktype.datalink_type
    elif isinstance(linktype, unicode):
        linktype = linktype.encode('utf-8')
    if isinstance(linktype, bytes):
        try:
            linktype = DLT.__getattr__(linktype)
        except AttributeError:
            raise ValueError("unknown DLT")
    return int(linktype)

cdef pcap_dumper_t* _get_dumper(object output, pcap_t* handle) except NULL:
    cdef pcap_dumper_t* dumper
    cdef int descriptor
    cdef FILE* f

    if isinstance(output, unicode):
        output = output.encode('utf-8')

    if isinstance(output, bytes):
        dumper = pcap_dump_open(handle, <const char*> output)
    else:
        try:
            descriptor = output.fileno()
        except (AttributeError, UnsupportedOperation):
            raise ValueError('the output stream must support fileno')
        f = fdopen(descriptor, b'w')
        dumper = pcap_dump_fopen(handle, f)

    if dumper == NULL:
        raise RuntimeError('could not get a proper dumper')
    return dumper

cdef _normalize_buf(object buf, int linktype):
    if isinstance(buf, PDU):
        try:
            buf = buf.rfind_pdu_by_datalink_type(linktype)
        except LibtinsException:
            raise ValueError("the PDU doesnt contain an appropriate PDU for datalink '%s'" % linktype)
        buf = buf.serialize()
    if isinstance(buf, memoryview):
        buf = buf.tobytes()
    if not isinstance(buf, bytes):
        buf = bytes(buf)
    return buf

cdef class PacketWriter(object):

    def __cinit__(self, linktype, output):
        self.linktype = _normalize_linktype(linktype)
        self.handle = pcap_open_dead(self.linktype, 65535)
        if self.handle == NULL:
            raise RuntimeError('could not get a pcap handle')
        self.dumper = _get_dumper(output, self.handle)
        self.output_lock = create_error_check_lock()

    def __init__(self, linktype, output):
        pass

    cdef _clean(self):
        if self.output_lock != NULL:
            destroy_error_check_lock(self.output_lock)
            self.output_lock = NULL
        if self.dumper != NULL:
            pcap_dump_close(self.dumper)
            self.dumper = NULL
        if self.handle != NULL:
            pcap_close(self.handle)
            self.handle = NULL

    cpdef stop(self):
        self._clean()

    def __dealloc__(self):
        self._clean()

    cdef int write_uchar_buf(self, unsigned char* buf, int length, long tv_sec=-1, int tv_usec=0) nogil:
        cdef pcap_pkthdr hdr
        cdef timeval tv

        if tv_sec == -1:
            tv_sec = <long> time(NULL)

        tv.tv_sec = tv_sec
        tv.tv_usec = tv_usec
        hdr.ts = tv
        hdr.caplen = length
        hdr.len = length

        # serialize the writes to output using a lock
        pthread_mutex_lock(self.output_lock)
        # pcap_dump might I/O block...
        pcap_dump(<unsigned char*> (<void*>self.dumper), &hdr, <unsigned char*> buf)
        pthread_mutex_unlock(self.output_lock)

        return 0

    cpdef write(self, object buf, long tv_sec=-1, int tv_usec=0):
        buf = _normalize_buf(buf, self.linktype)
        cdef unsigned char* uchar_buf = <unsigned char*> buf
        self.write_uchar_buf(uchar_buf, len(buf), tv_sec, tv_usec)


cdef class NonBlockingPacketWriter(PacketWriter):
    def __cinit__(self, linktype, output):
        self.linktype = _normalize_linktype(linktype)
        self.handle = pcap_open_dead(self.linktype, 65535)
        if self.handle == NULL:
            raise RuntimeError('could not get a pcap handle')
        self.dumper = _get_dumper(output, self.handle)
        self.output_lock = create_error_check_lock()
        self.stopping = 0

    def __init__(self, linktype, output):
        PacketWriter.__init__(self, linktype, output)
        self.q = deque()
        t = threading.Thread(target=self._flush_thread)
        t.start()

    def __dealloc__(self):
        self._clean()

    cpdef write(self, object buf, long tv_sec=-1, int tv_usec=0):
        buf = _normalize_buf(buf, self.linktype)
        self.q.append((tv_sec, tv_usec, len(buf), buf))

    cpdef stop(self):
        self.stopping = 1

    def _flush_thread(self):
        cdef pcap_dumper_t* dumper = self.dumper
        cdef size_t how_many, i
        cdef long* list_of_sec
        cdef int* list_of_usec
        cdef unsigned int* list_of_length
        cdef unsigned char** list_of_buf
        cdef pcap_pkthdr hdr
        cdef timeval tv
        temp_q = []

        while (self.stopping == 0) or (len(self.q) > 0):
            how_many = <int> len(self.q)
            if how_many == 0:
                sleep(1)
                continue
            # popleft is thread-safe, and we pop from the left (whereas sniff_and_store append on the right)
            temp_q = [self.q.popleft() for _ in range(how_many)]
            # copy from python containers to simple C containers, so that we can "nogil" after
            list_of_sec = <long*> malloc(how_many * sizeof(long))
            list_of_usec = <int*> malloc(how_many * sizeof(int))
            list_of_length = <unsigned int*> malloc(how_many * sizeof(unsigned int))
            list_of_buf = <unsigned char**> malloc(how_many * sizeof(unsigned char*))
            for i in range(how_many):
                list_of_sec[i], list_of_usec[i], list_of_length[i], list_of_buf[i] = temp_q[i]
            with nogil:
                # here the nogil is important: if pcap_dump actually IO/blocks, the ioloop can continue to run
                for i in range(how_many):
                    tv.tv_sec = list_of_sec[i]
                    tv.tv_usec = list_of_usec[i]
                    hdr.ts = tv
                    hdr.caplen = list_of_length[i]
                    hdr.len = list_of_length[i]
                    pcap_dump(<unsigned char*> (<void*>dumper), &hdr, <unsigned char*> (list_of_buf[i]))
                # we can safely flush data to disk, as it won't block the io loop
                pcap_dump_flush(dumper)
                free(list_of_buf)
                free(list_of_length)
                free(list_of_usec)
                free(list_of_sec)

        self._clean()

