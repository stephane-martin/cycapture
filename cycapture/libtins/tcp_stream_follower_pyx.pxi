# -*- coding: utf-8 -*-

cdef class TCPStreamFollower(object):
    """
    Reconstruct client and server TCP streams from individual PDUs.

    A `TCPStreamFollower` object will analyze the PDU's that you provide and reconstruct the clients and servers
    TCP streams that it can find.

    When a stream is updated, the python function `data_callback` is called. When a stream is closed, the
    python function `end_callback` is called.

    Callbacks are function that must accept one and only one parameter. The parameter is a :py:class:`~.TCPStream`
    object.

    Example::

        >>> from cycapture.libtins import TCPStream, TCPStreamFollower, PDU
        >>> pdus = get_some_pdus()        # get PDUs from somewhere (typically from pcap)
        >>> assert(all([isinstance(pdu, PDU) for pdu in pdus]))
        >>> def updated(stream):
        ...     assert(isinstance(stream, TCPStream))
        ...     print("Updated stream from {}:{} to {}:{}".format(
        ...         stream.client_addr, stream.client_port, stream.server_addr, stream.server_port)
        ...     )
        >>> follower = TCPStreamFollower(updated, None)         # we don't monitor closed streams
        >>> follower.feed(pdus)
    """
    def __cinit__(self, data_callback=None, end_callback=None):
        self.follower = new cppTCPStreamFollower()
        if data_callback is None:
            self.data_functor = new TCPStreamPyFunctor()
        elif callable(data_callback):
            self.data_functor = new TCPStreamPyFunctor(<PyObject*> data_callback)
        else:
            raise TypeError("data_callback and end_callback must be callables")

        if end_callback is None:
            self.end_functor = new TCPStreamPyFunctor()
        elif callable(end_callback):
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
        """
        __init__(data_callback=None, end_callback=None)

        Parameters
        ----------
        data_callback: function
            the python callback to call when a stream is updated
        end_callback: function
            the python callback to call when a stream is finished
        """

    cpdef feed(self, pdu_iterator):
        """
        feed(pdu_iterator)
        Follow TCP streams found in PDUs from `pdu_iterator` and call the appropriate

        If `pdu_iterator` contains objects that are not PDUs, they will be ignored.

        Parameters
        ----------
        pdu_iterator: a `PDU`, or a `list of PDU` or any iterator that gives `PDU`
        """
        cdef cppPDU* p

        if pdu_iterator is None:
            return
        if isinstance(pdu_iterator, PDU):
            pdu_iterator = [pdu_iterator]

        for pdu in pdu_iterator:
            if isinstance(pdu, PDU):
                p = (<PDU> pdu).base_ptr
                self.follower.follow_streams(p, p + 1, self.data_functor[0], self.end_functor[0])
