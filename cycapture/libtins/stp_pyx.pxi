# -*- coding: utf-8 -*-

cdef class bpdu_id(object):
    """
    BPDU identifier.

    Immutable, hashable, copyable, supports equality.
    """
    def __cinit__(self, int priority=0, int ext_id=0, ident=None):
        self._priority = small_uint4(<uint8_t> priority)
        self._ext_id = small_uint12(<uint16_t> ext_id)
        if not isinstance(ident, HWAddress):
            ident = HWAddress(ident)
        self._id = (<HWAddress> ident).ptr[0]

    def __init__(self, int priority=0, int ext_id=0, ident=None):
        """
        __init__(priority=0, ext_id=0, ident=None)

        Parameters
        ----------
        priority: int
        ext_id: int
        ident: :py:class:`~.HWAddress`
        """

    property priority:
        def __get__(self):
            return int(<uint8_t> self._priority)

    property ext_id:
        def __get__(self):
            return int(<uint16_t> self._ext_id)

    property id:
        def __get__(self):
            return HWAddress(self._id.to_string())

    def __hash__(self):
        return hash((self.priority, self.ext_id, <bytes> (self._id.to_string())))

    cpdef equals(self, other):
        if not isinstance(other, bpdu_id):
            return False
        return self.priority == (<bpdu_id> other).priority \
               and self.ext_id == (<bpdu_id> other).ext_id \
               and self._id.equals((<bpdu_id> other)._id)

    def __richcmp__(self, other, op):
        if op == 2:
            return (<bpdu_id> self).equals(other)
        elif op == 3:
            return not (<bpdu_id> self).equals(other)
        raise TypeError

    def __copy__(self):
        obj = bpdu_id()
        (<bpdu_id> obj)._priority = self._priority
        (<bpdu_id> obj)._ext_id = self._ext_id
        (<bpdu_id> obj)._id = self._id
        return obj

    @staticmethod
    cdef from_native(bpdu_id_type t):
        obj = bpdu_id()
        (<bpdu_id> obj)._priority = t.priority
        (<bpdu_id> obj)._ext_id = t.ext_id
        (<bpdu_id> obj)._id = t.id
        return obj

    cdef bpdu_id_type to_native(self):
        return bpdu_id_type(self._priority, self._ext_id, self._id)


cdef class STP(PDU):
    """
    Spanning Tree Protocol frame.
    """
    pdu_flag = PDU.STP
    pdu_type = PDU.STP
    bpdu_id_t = bpdu_id

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != STP:
            return

        self.ptr = new cppSTP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSTP* p = <cppSTP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    property proto_id:
        """
        Protocol ID field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.proto_id())
        def __set__(self, value):
            self.ptr.proto_id(<uint16_t> int(value))

    property proto_version:
        """
        Protocol Version field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.proto_version())
        def __set__(self, value):
            self.ptr.proto_version(<uint8_t> int(value))

    property bpdu_type:
        """
        BPDU Type field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.bpdu_type())
        def __set__(self, value):
            self.ptr.bpdu_type(<uint8_t> int(value))

    property bpdu_flags:
        """
        BPDU Flags field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.bpdu_flags())
        def __set__(self, value):
            self.ptr.bpdu_flags(<uint8_t> int(value))

    property root_path_cost:
        """
        Root Path Cost field (read-write, `uint32_t`)
        """
        def __get__(self):
            return int(self.ptr.root_path_cost())
        def __set__(self, value):
            self.ptr.root_path_cost(<uint32_t> int(value))

    property port_id:
        """
        Port ID field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.port_id())
        def __set__(self, value):
            self.ptr.port_id(<uint16_t> int(value))

    property msg_age:
        """
        Message Age field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.msg_age())
        def __set__(self, value):
            self.ptr.msg_age(<uint16_t> int(value))

    property max_age:
        """
        Maximum Age field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.max_age())
        def __set__(self, value):
            self.ptr.max_age(<uint16_t> int(value))

    property hello_time:
        """
        Hello Time field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.hello_time())
        def __set__(self, value):
            self.ptr.hello_time(<uint16_t> int(value))

    property fwd_delay:
        """
        Forward Delay field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.fwd_delay())
        def __set__(self, value):
            self.ptr.fwd_delay(<uint16_t> int(value))

    property root_id:
        """
        Root ID field (read-write, :py:class:`~.bpdu_id`)
        """
        def __get__(self):
            return bpdu_id.from_native(self.ptr.root_id())
        def __set__(self, value):
            if not isinstance(value, bpdu_id):
                priority, ext_id, ident = value
                value = bpdu_id(priority, ext_id, ident)
            self.ptr.root_id((<bpdu_id> value).to_native())

    property bridge_id:
        """
        Bridge ID field (read-write, :py:class:`~.bpdu_id`)
        """
        def __get__(self):
            return bpdu_id.from_native(self.ptr.bridge_id())
        def __set__(self, value):
            if not isinstance(value, bpdu_id):
                priority, ext_id, ident = value
                value = bpdu_id(priority, ext_id, ident)
            self.ptr.bridge_id((<bpdu_id> value).to_native())

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppSTP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppSTP*> ptr
