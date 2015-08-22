# -*- coding: utf-8 -*-

cdef class EthernetII(PDU):
    """
    Ethernet packet
    """
    pdu_flag = PDU.ETHERNET_II
    pdu_type = PDU.ETHERNET_II
    broadcast = HWAddress.broadcast

    def __cinit__(self, dest_src=None, buf=None, _raw=False):
        if _raw:
            return
        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None and dest_src is None:
            self.ptr = new cppEthernetII()
        elif buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            with nogil:
                self.ptr = new cppEthernetII(buf_addr, size)
        elif PyTuple_Check(dest_src) or PyList_Check(dest_src):
            dest, src = dest_src
            if src is None:
                src = HWAddress()
            if dest is None:
                dest = HWAddress()
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            self.ptr = new cppEthernetII(<cppHWAddress6> ((<HWAddress> dest).ptr[0]), <cppHWAddress6> ((<HWAddress> src).ptr[0]))
        elif isinstance(dest_src, HWAddress):
            self.ptr = new cppEthernetII(<cppHWAddress6> ((<HWAddress> dest_src).ptr[0]))
        else:
            self.ptr = new cppEthernetII(<cppHWAddress6> ((<HWAddress> (HWAddress(dest_src))).ptr[0]))

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dest_src=None, buf=None, _raw=False):
        pass

    property src_addr:
        def __get__(self):
            cdef cppHWAddress6 src = self.ptr.src_addr()
            return HWAddress(src.to_string())
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            self.ptr.src_addr(<cppHWAddress6>((<HWAddress> value).ptr[0]))

    property dst_addr:
        def __get__(self):
            cdef cppHWAddress6 dst = self.ptr.dst_addr()
            return HWAddress(dst.to_string())
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            self.ptr.dst_addr(<cppHWAddress6>((<HWAddress> value).ptr[0]))

    property payload_type:
        def __get__(self):
            return self.ptr.payload_type()

        def __set__(self, value):
            self.ptr.payload_type(<uint16_t> int(value))




