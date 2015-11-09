# -*- coding: utf-8 -*-

cdef class BootP(PDU):
    """
    BootP packet
    """
    pdu_flag = PDU.BOOTP
    pdu_type = PDU.BOOTP

    OpCodes = make_enum('BootPOpCodes', 'OpCodes', 'The different opcodes BootP messages', {
        'BOOTREQUEST': BOOTP_BOOTREQUEST,
        'BOOTREPLY': BOOTP_BOOTREPLY
    })

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != BootP:
            return

        self.ptr = new cppBootP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppBootP* p = <cppBootP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    property opcode:
        """
        OpCode field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.opcode())
        def __set__(self, value):
            self.ptr.opcode(<uint8_t> int(value))

    property htype:
        """
        htype field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.htype())
        def __set__(self, value):
            self.ptr.htype(<uint8_t> int(value))

    property hlen:
        """
        hlen field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.hlen())
        def __set__(self, value):
            self.ptr.hlen(<uint8_t> int(value))

    property hops:
        """
        hops field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.hops())
        def __set__(self, value):
            self.ptr.hops(<uint8_t> int(value))

    property xid:
        """
        xid field (read-write, `uint32_t`)
        """
        def __get__(self):
            return int(self.ptr.xid())
        def __set__(self, value):
            self.ptr.xid(<uint32_t> int(value))

    property secs:
        """
        secs field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.secs())
        def __set__(self, value):
            self.ptr.secs(<uint16_t> int(value))

    property padding:
        """
        padding field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.padding())
        def __set__(self, value):
            self.ptr.padding(<uint16_t> int(value))

    property ciaddr:
        """
        ciaddr field (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            return IPv4Address(<bytes> (self.ptr.ciaddr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.ciaddr((<IPv4Address> value).ptr[0])

    property yiaddr:
        """
        yiaddr field (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            return IPv4Address(<bytes> (self.ptr.yiaddr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.yiaddr((<IPv4Address> value).ptr[0])

    property siaddr:
        """
        siaddr field (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            return IPv4Address(<bytes> (self.ptr.siaddr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.siaddr((<IPv4Address> value).ptr[0])

    property giaddr:
        """
        giaddr field (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            return IPv4Address(<bytes> (self.ptr.giaddr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.giaddr((<IPv4Address> value).ptr[0])

    property chaddr:
        """
        chaddr field (read-write, `bytes` like ``b"00:01:02:03:04:05:06:07:08:09:10:11:12:13:14:ff"``)
        """

        def __get__(self):
            return <bytes> (self.ptr.chaddr().to_string())
        def __set__(self, value):
            l = bytes(value).split(':')
            if len(l) > 16:
                raise ValueError
            if any([int(s, 16) > 255 for s in l]):
                raise ValueError
            value = ":".join([s.zfill(2) for s in l])
            bootp_set_chaddr(self.ptr[0], cppHWAddress16(<string> value))

    property sname:
        """
        sname field (read-write, `bytes` with length <= 64)
        """
        def __get__(self):
            return <bytes> (self.ptr.sname()[:64])
        def __set__(self, value):
            value = (bytes(value)[:64]).ljust(64, '\x00')
            self.ptr.sname(<uint8_t*> value)

    property file:
        """
        file field (read-write, `bytes` with length <= 128)
        """
        def __get__(self):
            return <bytes> (self.ptr.file()[:128])
        def __set__(self, value):
            value = (bytes(value)[:128]).ljust(128, '\x00')
            self.ptr.file(<uint8_t*> value)

    property vend:
        """
        vend field (read-write, `bytes`)
        """
        def __get__(self):
            cdef vector[uint8_t] v = <vector[uint8_t]> ((<const cppBootP*> self.ptr).vend())
            return <bytes> ((&(v[0]))[:v.size()])

        def __set__(self, value):
            value = bytes(value)
            cdef string s = value
            cdef vector[uint8_t] v
            v.assign(s.c_str(), s.c_str() + s.size())
            self.ptr.vend(v)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppBootP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppBootP*> ptr
