# -*- coding: utf-8 -*-
"""
Ethernet packet python class
"""

cdef factory_ethernet_ii(cppPDU* ptr, uint8_t* buf, int size, object parent):
    if ptr is NULL and buf is NULL:
        return EthernetII()
    obj = EthernetII(_raw=True)
    obj.ptr = new cppEthernetII(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppEthernetII*> ptr
    obj.base_ptr = <cppPDU*> obj.ptr
    obj.parent = parent
    return obj

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
        elif buf is None and dest_src is None:
            self.ptr = new cppEthernetII()
        elif buf is not None:
            if PyBytes_Check(buf):
                self.ptr = new cppEthernetII(<uint8_t*> PyBytes_AS_STRING(buf), <uint32_t> PyBytes_Size(buf))
            elif isinstance(buf, bytearray):
                buf = memoryview(buf)
                self.ptr = new cppEthernetII(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            elif isinstance(buf, memoryview):
                if buf.itemsize == 1 and buf.ndim == 1:
                    self.ptr = new cppEthernetII(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
                else:
                    raise ValueError("the memoryview doesn't have the proper format")
            elif isinstance(buf, cy_memoryview):
                if buf.itemsize == 1 and buf.ndim == 1:
                    self.ptr = new cppEthernetII(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
                else:
                    raise ValueError("the typed memoryview doesn't have the proper format")
            else:
                raise ValueError("don't know what to do with type '%s'" % type(buf))
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


