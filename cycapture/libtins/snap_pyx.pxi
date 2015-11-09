# -*- coding: utf-8 -*-

cdef class SNAP(PDU):
    """
    SNAP frame.

    Note that this PDU contains the 802.3 LLC structure + SNAP frame. So far only unnumbered information structure is
    supported.
    """
    pdu_flag = PDU.SNAP
    pdu_type = PDU.SNAP

    def __cinit__(self, _raw=False):
        if _raw or type(self) != SNAP:
            return

        self.ptr = new cppSNAP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSNAP* p = <cppSNAP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()

        The constructor sets the `dsap` and `ssap` fields to ``0xaa``, and the `id` field to ``3``.
        """

    property org_code:
        """
        Organization Code field (read-write, `24 bits int`)
        """
        def __get__(self):
            return int(<uint32_t> self.ptr.org_code())
        def __set__(self, value):
            self.ptr.org_code(small_uint24(<uint32_t> int(value)))

    property eth_type:
        """
        Ethernet Type field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.eth_type())
        def __set__(self, value):
            self.ptr.eth_type(<uint16_t> int(value))

    property control:
        """
        Control field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.control())
        def __set__(self, value):
            self.ptr.control(<uint8_t> int(value))

    property dsap:
        """
        DSAP field (read-only)
        """
        def __get__(self):
            return int(self.ptr.dsap())

    property ssap:
        """
        SSAP field (read-only)
        """
        def __get__(self):
            return int(self.ptr.ssap())

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppSNAP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppSNAP*> ptr
