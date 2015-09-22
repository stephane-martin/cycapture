# -*- coding: utf-8 -*-

cdef extern from "tins/tcp_stream.h" namespace "Tins" nogil:
    cppclass cppTCPStreamFollower "Tins::TCPStreamFollower":
        cppTCPStreamFollower()
        # except+ because the functors called by follow_streams may throw exceptions
        void follow_streams[ForwardIterator, DataFunctor, EndFunctor](ForwardIterator start, ForwardIterator end, DataFunctor data_fun, EndFunctor end_fun) except+


cdef extern from "py_tcp_stream_functor.h" namespace "Tins":
    cppclass TCPStreamPyFunctor:
        TCPStreamPyFunctor(PyObject* callabl)


cdef extern from "py_pdu_iterator.h" namespace "Tins":
    cppclass PDUIterator:
        PDUIterator();
        PDUIterator(PyObject* it)


cdef class TCPStreamFollower(object):
    cdef cppTCPStreamFollower* follower
    cdef TCPStreamPyFunctor* data_functor
    cdef TCPStreamPyFunctor* end_functor
    cpdef feed(self, list_of_pdu)


