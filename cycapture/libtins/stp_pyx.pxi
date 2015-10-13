# -*- coding: utf-8 -*-

cdef class bpdu_id(object):


    def __init__(self, priority=None, ext_id=None, ident=None):
        if priority is not None:
            self.priority = priority
        if ext_id is not None:
            self.ext_id = ext_id
        if ident is not None:
            self.id = ident

    property priority:
        def __get__(self):
            return int(<uint8_t> self._priority)
        def __set__(self, value):
            self._priority = small_uint4(<uint8_t> int(value))

    property ext_id:
        def __get__(self):
            return int(<uint16_t> self._ext_id)
        def __set__(self, value):
            self._ext_id = small_uint12(<uint16_t> int(value))

    property id:
        def __get__(self):
            return HWAddress(<bytes> (self._id.to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            self._id = (<HWAddress> value).ptr[0]

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
    pdu_flag = PDU.STP
    pdu_type = PDU.STP

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != STP:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppSTP()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppSTP(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppSTP* p = <cppSTP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, buf=None, _raw=False):
        pass

    property proto_id:
        def __get__(self):
            return int(self.ptr.proto_id())
        def __set__(self, value):
            self.ptr.proto_id(<uint16_t> int(value))

    property proto_version:
        def __get__(self):
            return int(self.ptr.proto_version())
        def __set__(self, value):
            self.ptr.proto_version(<uint8_t> int(value))

    property bpdu_type:
        def __get__(self):
            return int(self.ptr.bpdu_type())
        def __set__(self, value):
            self.ptr.bpdu_type(<uint8_t> int(value))

    property bpdu_flags:
        def __get__(self):
            return int(self.ptr.bpdu_flags())
        def __set__(self, value):
            self.ptr.bpdu_flags(<uint8_t> int(value))

    property root_path_cost:
        def __get__(self):
            return int(self.ptr.root_path_cost())
        def __set__(self, value):
            self.ptr.root_path_cost(<uint32_t> int(value))

    property port_id:
        def __get__(self):
            return int(self.ptr.port_id())
        def __set__(self, value):
            self.ptr.port_id(<uint16_t> int(value))

    property msg_age:
        def __get__(self):
            return int(self.ptr.msg_age())
        def __set__(self, value):
            self.ptr.msg_age(<uint16_t> int(value))
    property max_age:
        def __get__(self):
            return int(self.ptr.max_age())
        def __set__(self, value):
            self.ptr.max_age(<uint16_t> int(value))

    property hello_time:
        def __get__(self):
            return int(self.ptr.hello_time())
        def __set__(self, value):
            self.ptr.hello_time(<uint16_t> int(value))

    property fwd_delay:
        def __get__(self):
            return int(self.ptr.fwd_delay())
        def __set__(self, value):
            self.ptr.fwd_delay(<uint16_t> int(value))

    property root_id:
        def __get__(self):
            return bpdu_id.from_native(self.ptr.root_id())
        def __set__(self, value):
            if not isinstance(value, bpdu_id):
                priority, ext_id, ident = value
                value = bpdu_id(priority, ext_id, ident)
            self.ptr.root_id((<bpdu_id> value).to_native())

    property bridge_id:
        def __get__(self):
            return bpdu_id.from_native(self.ptr.bridge_id())
        def __set__(self, value):
            if not isinstance(value, bpdu_id):
                priority, ext_id, ident = value
                value = bpdu_id(priority, ext_id, ident)
            self.ptr.bridge_id((<bpdu_id> value).to_native())
