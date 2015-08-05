# -*- coding: utf-8 -*-
"""
IP packet python class
"""

cdef factory_ip(cppPDU* ptr, uint8_t* buf, int size, object parent):
    if ptr is NULL and buf is NULL:
        return IP()
    obj = IP(_raw=True)
    obj.ptr = new cppIP(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppIP*> ptr
    obj.base_ptr = <cppPDU*> obj.ptr
    obj.parent = parent
    return obj


cdef class IP(PDU):
    """
    IP packet
    """
    pdu_flag = PDU.IP
    pdu_type = PDU.IP

    CONTROL = IP_OPT_CLASS_CONTROL
    MEASUREMENT = IP_OPT_CLASS_MEASUREMENT
    END = IP_OPT_NUMBER_END
    NOOP = IP_OPT_NUMBER_NOOP
    SEC = IP_OPT_NUMBER_SEC
    LSSR = IP_OPT_NUMBER_LSSR
    TIMESTAMP = IP_OPT_NUMBER_TIMESTAMP
    EXTSEC = IP_OPT_NUMBER_EXTSEC
    RR = IP_OPT_NUMBER_RR
    SID = IP_OPT_NUMBER_SID
    SSRR = IP_OPT_NUMBER_SSRR
    MTUPROBE = IP_OPT_NUMBER_MTUPROBE
    MTUREPLY = IP_OPT_NUMBER_MTUREPLY
    EIP = IP_OPT_NUMBER_EIP
    TR = IP_OPT_NUMBER_TR
    ADDEXT = IP_OPT_NUMBER_ADDEXT
    RTRALT = IP_OPT_NUMBER_RTRALT
    SDB = IP_OPT_NUMBER_SDB
    DPS = IP_OPT_NUMBER_DPS
    UMP = IP_OPT_NUMBER_UMP
    QS = IP_OPT_NUMBER_QS

    def __cinit__(self, dest_src_ips=None, buf=None, _raw=False):
        if _raw:
            return
        elif buf is None and dest_src_ips is None:
            self.ptr = new cppIP()
        elif buf is not None:
            # construct from a buffer
            if PyBytes_Check(buf):           # (if buf a bytes object)
                # avoid a copy of buf: directly pass the real address
                # this is OK as cppIP constructor takes a *const* uint8_t parameter
                self.ptr = new cppIP(<uint8_t*> PyBytes_AS_STRING(buf), <uint32_t> PyBytes_Size(buf))
            elif isinstance(buf, bytearray):
                # avoid a copy of the bytearray
                buf = memoryview(buf)
                self.ptr = new cppIP(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            elif isinstance(buf, memoryview):
                if buf.itemsize == 1 and buf.ndim == 1:
                    self.ptr = new cppIP(<uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
                else:
                    raise ValueError("the memoryview doesn't have the proper format")
            elif isinstance(buf, cy_memoryview):
                if buf.itemsize == 1 and buf.ndim == 1:
                    self.ptr = new cppIP(<uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), <uint32_t> len(buf))
                else:
                    raise ValueError("the typed memoryview doesn't have the proper format")
            else:
                raise ValueError("don't know what to do with type '%s'" % type(buf))
        elif PyTuple_Check(dest_src_ips) or PyList_Check(dest_src_ips):
            dest, src = dest_src_ips
            if src is None:
                src = IPv4Address()
            if dest is None:
                dest = IPv4Address()
            if not isinstance(src, IPv4Address):
                src = IPv4Address(src)
            if not isinstance(dest, IPv4Address):
                dest = IPv4Address(dest)
            self.ptr = new cppIP(<cppIPv4Address> ((<IPv4Address> dest).ptr[0]), <cppIPv4Address> ((<IPv4Address> src).ptr[0]))
        elif isinstance(dest_src_ips, IPv4Address):
            self.ptr = new cppIP(<cppIPv4Address> ((<IPv4Address> dest_src_ips).ptr[0]))
        else:
            self.ptr = new cppIP(<cppIPv4Address> (IPv4Address(dest_src_ips)).ptr[0])
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dest_src_ips=None, buf=None, _raw=False):
        pass

    cpdef eol(self):
        self.ptr.eol()

    cpdef noop(self):
        self.ptr.noop()

    property head_len:
        def __get__(self):
            return <uint8_t> self.ptr.head_len()

    property tos:
        def __get__(self):
            return <uint8_t> self.ptr.tos()
        def __set__(self, value):
            cdef uint8_t v = <uint8_t> int(value)
            self.ptr.tos(v)

    property tot_len:
        def __get__(self):
            return <uint16_t> self.ptr.tot_len()

    property id:
        def __get__(self):
            return <uint16_t> self.ptr.ident()
        def __set__(self, value):
            cdef uint16_t v = <uint16_t> int(value)
            self.ptr.ident(v)

    property frag_off:
        def __get__(self):
            return <uint16_t> self.ptr.frag_off()
        def __set__(self, value):
            cdef uint16_t v = <uint16_t> int(value)
            self.ptr.frag_off(v)

    property ttl:
        def __get__(self):
            return <uint8_t> self.ptr.ttl()
        def __set__(self, value):
            cdef uint8_t v = <uint8_t> int(value)
            self.ptr.ttl(v)

    property protocol:
        def __get__(self):
            return <uint8_t> self.ptr.protocol()
        def __set__(self, value):
            cdef uint8_t v = <uint8_t> int(value)
            self.ptr.protocol(v)

    property checksum:
        def __get__(self):
            return <uint16_t> self.ptr.checksum()

    property src_addr:
        def __get__(self):
            cdef cppIPv4Address src = self.ptr.src_addr()
            return IPv4Address(convert_to_big_endian_int(src))
        def __set__(self, new_src):
            cdef string src
            if isinstance(new_src, IPv4Address):
                self.ptr.src_addr((<IPv4Address> new_src).ptr[0])
            else:
                src = <string> bytes(new_src)
                self.ptr.src_addr(cppIPv4Address(src))

    property dst_addr:
        def __get__(self):
            cdef cppIPv4Address dst = self.ptr.dst_addr()
            return IPv4Address(convert_to_big_endian_int(dst))
        def __set__(self, new_dst):
            cdef string dst
            if isinstance(new_dst, IPv4Address):
                self.ptr.dst_addr((<IPv4Address> new_dst).ptr[0])
            else:
                dst = <string> bytes(new_dst)
                self.ptr.dst_addr(cppIPv4Address(dst))

    property version:
        def __get__(self):
            return <uint8_t> self.ptr.version()
        def __set__(self, value):
            self.ptr.version(small_uint4(<uint8_t>int(value)))

    cpdef cpp_bool is_fragmented(self):
        return self.ptr.is_fragmented()

    property stream_identifier:
        def __get__(self):
            try:
                return <uint16_t> self.ptr.stream_identifier()
            except RuntimeError:
                return None

        def __set__(self, value):
            self.ptr.stream_identifier(<uint16_t>int(value))

    cpdef record_route(self, pointer, routes):
        if isinstance(routes, IPv4Address) or isinstance(routes, bytes):
            routes = [routes]
        cdef vector[cppIPv4Address] v
        for addr in routes:
            v.push_back(IPv4Address(addr).ptr[0])
        cdef cppIP.generic_route_option_type r = cppIP.generic_route_option_type(<uint8_t>int(pointer), v)
        self.ptr.record_route(r)

    cpdef get_record_route(self):
        cdef cppIP.generic_route_option_type r
        try:
            r = self.ptr.record_route()
        except RuntimeError:
            return None
        routes = []
        cdef vector[cppIPv4Address] v = r.routes
        for i in range(v.size()):
            routes.append(IPv4Address(convert_to_big_endian_int(v[i])))
        return int(r.pointer), routes

    cpdef lsrr(self, pointer, routes):
        if isinstance(routes, IPv4Address) or isinstance(routes, bytes):
            routes = [routes]
        cdef vector[cppIPv4Address] v
        for addr in routes:
            v.push_back(IPv4Address(addr).ptr[0])
        cdef cppIP.generic_route_option_type r = cppIP.generic_route_option_type(<uint8_t>int(pointer), v)
        self.ptr.lsrr(r)

    cpdef get_lsrr(self):
        cdef cppIP.generic_route_option_type r
        try:
            r = self.ptr.lsrr()
        except RuntimeError:
            return None
        routes = []
        cdef vector[cppIPv4Address] v = r.routes
        for i in range(v.size()):
            routes.append(IPv4Address(convert_to_big_endian_int(v[i])))
        return int(r.pointer), routes

    cpdef ssrr(self, pointer, routes):
        if isinstance(routes, IPv4Address) or isinstance(routes, bytes):
            routes = [routes]
        cdef vector[cppIPv4Address] v
        for addr in routes:
            v.push_back(IPv4Address(addr).ptr[0])
        cdef cppIP.generic_route_option_type r = cppIP.generic_route_option_type(<uint8_t>int(pointer), v)
        self.ptr.ssrr(r)

    cpdef get_ssrr(self):
        cdef cppIP.generic_route_option_type r
        try:
            r = self.ptr.ssrr()
        except RuntimeError:
            return None
        routes = []
        cdef vector[cppIPv4Address] v = r.routes
        for i in range(v.size()):
            routes.append(IPv4Address(convert_to_big_endian_int(v[i])))
        return int(r.pointer), routes
