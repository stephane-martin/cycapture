# -*- coding: utf-8 -*-

cdef class Loopback(PDU):
    """
    Loopback PDU
    """
    pdu_flag = PDU.LOOPBACK
    pdu_type = PDU.LOOPBACK
    datalink_type = DLT_LOOP

    def __cinit__(self, _raw=False):
        if _raw or type(self) != Loopback:
            return

        self.ptr = new cppLoopback()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppLoopback* p = <cppLoopback*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if not BSD_OR_ZERO:
            raise RuntimeError("The Loopback.send method is not available in this platform")
        if sender is None:
            raise ValueError("sender can't be None")
        if iface is None:
            raise ValueError("iface can't be None")
        self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).interface)

    property family:
        """
        family identifier (read-write, `uint32_t`)
        """
        def __get__(self):
            return int(self.ptr.family())
        def __set__(self, value):
            self.ptr.family(<uint32_t> int(value))

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppLoopback(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppLoopback*> ptr
