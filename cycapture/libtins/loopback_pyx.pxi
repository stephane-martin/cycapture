# -*- coding: utf-8 -*-

cdef class Loopback(PDU):
    pdu_flag = PDU.LOOPBACK
    pdu_type = PDU.LOOPBACK
    datalink_type = DLT_LOOP

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != BootP:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppLoopback()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppLoopback(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppLoopback* p = <cppLoopback*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if BSD_OR_ZERO:
            if sender is None:
                raise ValueError("sender can't be None")
            if iface is None:
                raise ValueError("iface can't be None")
            self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).ptr[0])
        else:
            raise RuntimeError("The Loopback.send method is not available in this platform")

    property family:
        def __get__(self):
            return int(self.ptr.family())
        def __set__(self, value):
            self.ptr.family(<uint32_t> int(value))
