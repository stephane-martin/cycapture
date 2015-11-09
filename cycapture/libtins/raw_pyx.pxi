# -*- coding: utf-8 -*-
"""
RAW packet python class
"""

cdef class RAW(PDU):
    """
    RAW PDU packet.

    This class is a wrapper over a byte array. It can be used to hold
    the payload sent over transport layer protocols (such as TCP or UDP).

    RAW packets can be converted to another PDU using the `to` method::

    >>> from cycapture.libtins import RAW, DNS, DHCP
    >>> raw = RAW(...)
    >>> dhcp = raw.to(DHCP)     # if we know the payload is in fact a DHCP packet, we can convert
    >>> dns = raw.to(DNS)       # if the conversion fails, a MalformedException is raised

    RAW.matches_response always returns ``True``.
    """
    pdu_flag = PDU.RAW
    pdu_type = PDU.RAW

    def __cinit__(self, data=b'', _raw=False):
        if _raw:
            return
        data = "" if data is None else bytes(data)
        self.ptr = new cppRAW(<string> data)
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, data=b''):
        """
        __init__(data=b'')

        Parameters
        ----------
        data: bytes
            the payload that will be copied into the RAW PDU
        """
        pass

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    property payload:
        """
        The payload (read-write, `bytes`)
        """
        def __get__(self):
            cdef const uint8_t* buf = &(self.ptr.payload()[0])
            cdef int size = self.ptr.payload().size()
            return <bytes>(buf[:size])

        def __set__(self, value):
            if not isinstance(value, bytes):
                value = bytes(value)
            cdef uint8_t* buf = <uint8_t*> (<bytes>value)
            cdef vector[uint8_t] v
            v.assign(buf, buf + len(value))
            self.ptr.payload(v)

    cpdef to(self, pdu_class):
        """
        to(pdu_class)
        Convert the payload to another concrete PDU (the payload is copied).

        Parameters
        ----------
        pdu_class: a concrete PDU

        Returns
        -------
        pdu: an instance of pdu_class

        Raises
        ------
        exception: :py:class:`~.MalformedPacket`
            if the payload can't be parsed to `pdu_class`
        """
        if not issubclass(pdu_class, PDU):
            raise ValueError("Don't know what to to with: %s" % pdu_class.__name__)
        obj = pdu_class.__new__(pdu_class, _raw=True)
        cdef cppPDU* ptr = (<PDU> obj).replace_ptr_with_buf(&(self.ptr.payload()[0]), self.ptr.payload().size())
        (<PDU> obj).base_ptr = ptr
        (<PDU> obj).parent = None
        return obj

    property payload_size:
        """
        The payload size (read-only)
        """
        def __get__(self):
            return int(self.ptr.payload_size())

    cdef equals(self, other):
        if not isinstance(other, PDU):
            return False
        if isinstance(other, RAW):
            #return self.ptr.payload() == (<RAW> other).ptr.payload() todo: complete
            pass
        else:
            try:
                s = self.to(type(other))
            except MalformedPacket:
                return False
            return s == other

    def __richcmp__(self, other, op):
        if op == 2:
            return (<RAW> self).equals(other)
        elif op == 3:
            return not (<RAW> self).equals(other)
        raise ValueError("operation not supported")

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppRAW(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppRAW*> ptr

Raw = RAW
