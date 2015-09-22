# -*- coding: utf-8 -*-

def dummy_callback(stream):
    return True

cdef class TCPStreamFollower(object):
    def __cinit__(self, data_callback=None, end_callback=None):
        self.follower = new cppTCPStreamFollower()
        if data_callback is None:
            data_callback = dummy_callback
        if end_callback is None:
            end_callback = dummy_callback

        # check that the callbacks are functions and accept one and only argument
        if (not callable(data_callback)) or (not callable(end_callback)):
            raise TypeError("data_callback and end_callback must be callables")

        self.data_functor = new TCPStreamPyFunctor(<PyObject*> data_callback)
        self.end_functor = new TCPStreamPyFunctor(<PyObject*> end_callback)

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
        if PySequence_Check(list_of_pdu):
            if len(list_of_pdu) == 0:
                return
            list_of_pdu = iter(list_of_pdu)
        if not PyIter_Check(list_of_pdu):
            raise TypeError("don't know what to do with list_of_pdu type: %s" % type(list_of_pdu))
        cdef PDUIterator start = PDUIterator(<PyObject*> list_of_pdu)
        cdef PDUIterator end
        self.follower.follow_streams(start, end, self.data_functor[0], self.end_functor[0])

