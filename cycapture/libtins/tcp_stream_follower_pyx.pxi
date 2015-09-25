# -*- coding: utf-8 -*-


cdef class TCPStreamFollower(object):
    def __cinit__(self, data_callback=None, end_callback=None):
        self.follower = new cppTCPStreamFollower()

        if data_callback is None:
            self.data_functor = new TCPStreamPyFunctor()
        else:
            if callable(data_callback):
                self.data_functor = new TCPStreamPyFunctor(<PyObject*> data_callback)
            else:
                raise TypeError("data_callback and end_callback must be callables")

        if end_callback is None:
            self.end_functor = new TCPStreamPyFunctor()
        else:
            if callable(end_callback):
                self.end_functor = new TCPStreamPyFunctor(<PyObject*> end_callback)
            else:
                raise TypeError("data_callback and end_callback must be callables")


    def __dealloc__(self):
        if self.end_functor != NULL:
            del self.end_functor
            self.end_functor = NULL
        if self.data_functor != NULL:
            del self.data_functor
            self.data_functor = NULL
        if self.follower != NULL:
            del self.follower
            self.follower = NULL

    def __init__(self, data_callback=None, end_callback=None):
        pass

    cpdef feed(self, list_of_pdu):
        cdef cppPDU* p = NULL
        if list_of_pdu is None:
            return
        if isinstance(list_of_pdu, PDU):
            list_of_pdu = [list_of_pdu]

        for pdu in list_of_pdu:
            if isinstance(pdu, PDU):
                p = (<PDU> pdu).base_ptr
                self.follower.follow_streams(p, p + 1, self.data_functor[0], self.end_functor[0])
