

cdef class NonBlockingSniffer(Sniffer):
    cdef bool _nonblocking_mode
    cdef object python_callback
    cdef object loop
    cdef bytes loop_type
    cdef object descriptor
    cdef object container
    cdef object old_status
    cdef object writer
    cpdef sniff_callback(self, callback, int max_p=?)
    cpdef sniff_and_store(self, container, f=?, int max_p=?)
    cpdef set_loop(self, loop, loop_type=?)
    cpdef stop(self)

