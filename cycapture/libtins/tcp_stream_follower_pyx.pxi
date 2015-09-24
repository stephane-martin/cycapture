# -*- coding: utf-8 -*-

cdef void dummy_f(cppTCPStream& s):
    pass

cdef class TCPStreamFollower(object):
    def __cinit__(self, data_callback=None, end_callback=None):
        self.follower = new cppTCPStreamFollower()

        if data_callback is None:
            self.data_functor = NULL
        else:
            if callable(data_callback):
                self.data_functor = new TCPStreamPyFunctor(<PyObject*> data_callback)
            else:
                raise TypeError("data_callback and end_callback must be callables")

        if end_callback is None:
            self.end_functor = NULL
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
        if list_of_pdu is None:
            return
        if isinstance(list_of_pdu, PDU):
            list_of_pdu = [list_of_pdu]

        cdef vector[cppPDU*] v
        for pdu in list_of_pdu:
            if not isinstance(pdu, PDU):
                continue
            v.push_back((<PDU> pdu).base_ptr)
            #print(pdu)
            try:
                if self.data_functor != NULL and self.end_functor != NULL:
                    self.follower.follow_streams(v.begin(), v.end(), self.data_functor[0], self.end_functor[0])
                elif self.data_functor == NULL and self.end_functor == NULL:
                    self.follower.follow_streams(v.begin(), v.end(), dummy_f, dummy_f)
                elif self.data_functor != NULL:
                    self.follower.follow_streams(v.begin(), v.end(), self.data_functor[0], dummy_f)
                else:
                    self.follower.follow_streams(v.begin(), v.end(), dummy_f, self.end_functor[0])
            finally:
                v.pop_back()

