# -*- coding: utf-8 -*-

cdef class BootP(PDU):
    pdu_flag = PDU.BOOTP
    pdu_type = PDU.BOOTP

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != BootP:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppBootP()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppBootP(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppBootP* p = <cppBootP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    property opcode:
        def __get__(self):
            return int(self.ptr.opcode())
        def __set__(self, value):
            self.ptr.opcode(<uint8_t> int(value))

    property htype:
        def __get__(self):
            return int(self.ptr.htype())
        def __set__(self, value):
            self.ptr.htype(<uint8_t> int(value))

    property hlen:
        def __get__(self):
            return int(self.ptr.hlen())
        def __set__(self, value):
            self.ptr.hlen(<uint8_t> int(value))

    property hops:
        def __get__(self):
            return int(self.ptr.hops())
        def __set__(self, value):
            self.ptr.hops(<uint8_t> int(value))

    property xid:
        def __get__(self):
            return int(self.ptr.xid())
        def __set__(self, value):
            self.ptr.xid(<uint32_t> int(value))

    property secs:
        def __get__(self):
            return int(self.ptr.secs())
        def __set__(self, value):
            self.ptr.secs(<uint16_t> int(value))

    property padding:
        def __get__(self):
            return int(self.ptr.padding())
        def __set__(self, value):
            self.ptr.padding(<uint16_t> int(value))

    property ciaddr:
        def __get__(self):
            return IPv4Address(<bytes> (self.ptr.ciaddr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.ciaddr((<IPv4Address> value).ptr[0])

    property yiaddr:
        def __get__(self):
            return IPv4Address(<bytes> (self.ptr.yiaddr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.yiaddr((<IPv4Address> value).ptr[0])

    property siaddr:
        def __get__(self):
            return IPv4Address(<bytes> (self.ptr.siaddr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.siaddr((<IPv4Address> value).ptr[0])

    property giaddr:
        def __get__(self):
            return IPv4Address(<bytes> (self.ptr.giaddr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.giaddr((<IPv4Address> value).ptr[0])

    property chaddr:
        def __get__(self):
            return <bytes> (self.ptr.chaddr().to_string())
        def __set__(self, value):
            value = bytes(value)
            raise NotImplementedError
            # todo: self.ptr.chaddr(cppHWAddress16(<string> value))
            # template<size_t n> void chaddr(const HWAddress<n> &new_chaddr)

    property sname:
        def __get__(self):
            # todo: get the whole buf ?
            return <bytes> (self.ptr.sname())
        def __set__(self, value):
            value = (bytes(value)[:64]).ljust(64, '\x00')
            self.ptr.sname(<uint8_t*> value)

    property file:
        def __get__(self):
            # todo: get the whole buf ?
            return <bytes> (self.ptr.file())
        def __set__(self, value):
            value = (bytes(value)[:128]).ljust(128, '\x00')
            self.ptr.file(<uint8_t*> value)

    property vend:
        def __get__(self):
            cdef vector[uint8_t] v = <vector[uint8_t]> ((<const cppBootP*> self.ptr).vend())
            return <bytes> ((&(v[0]))[:v.size()])

        def __set__(self, value):
            value = bytes(value)
            cdef string s = value
            cdef vector[uint8_t] v
            v.assign(s.c_str(), s.c_str() + s.size())
            self.ptr.vend(v)


