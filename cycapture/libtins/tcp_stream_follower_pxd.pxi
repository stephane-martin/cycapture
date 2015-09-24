# -*- coding: utf-8 -*-

cdef extern from "tins/utils.h" namespace "Tins":
    (cppPDU&) dereference_until_pdu "Tins::Utils::dereference_until_pdu" [Typ](Typ &value)


cdef extern from "tins/tcp_stream.h" namespace "Tins":
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
        PDUIterator& preinc "operator++" ()
        PDUIterator& operator=(const PDUIterator& other)

    cpp_bool operator==(const PDUIterator& lhs, const PDUIterator& rhs)
    cpp_bool operator!=(const PDUIterator& lhs, const PDUIterator& rhs)




cdef class TCPStreamFollower(object):
    cdef cppTCPStreamFollower* follower
    cdef TCPStreamPyFunctor* data_functor
    cdef TCPStreamPyFunctor* end_functor
    cpdef feed(self, list_of_pdu)

