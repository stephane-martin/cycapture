# -*- coding: utf-8 -*-

cdef class PPPoE(PDU):
    """
    Point-to-point protocol over Ethernet packet
    """
    pdu_flag = PDU.PPPOE
    pdu_type = PDU.PPPOE

    TagTypes = make_enum('PPPoE_TagTypes', 'TagTypes', 'Tag types enum', {
        'END_OF_LIST': PPPoE_END_OF_LIST,
        'SERVICE_NAME': PPPoE_SERVICE_NAME,
        'AC_NAME': PPPoE_AC_NAME,
        'HOST_UNIQ': PPPoE_HOST_UNIQ,
        'AC_COOKIE': PPPoE_AC_COOKIE,
        'VENDOR_SPECIFIC': PPPoE_VENDOR_SPECIFIC,
        'RELAY_SESSION_ID': PPPoE_RELAY_SESSION_ID,
        'SERVICE_NAME_ERROR': PPPoE_SERVICE_NAME_ERROR,
        'AC_SYSTEM_ERROR': PPPoE_AC_SYSTEM_ERROR,
        'GENERIC_ERROR': PPPoE_GENERIC_ERROR
    })

    def __cinit__(self, _raw=False):
        if _raw or type(self) != PPPoE:
            return

        self.ptr = new cppPPPoE()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppPPPoE* p = <cppPPPoE*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()

        The default constructor sets the version and type fields to ``0x1``.
        """

    property version:
        """
        version field (read-write, `4 bits int`)
        """
        def __get__(self):
            return int(<uint8_t> self.ptr.version())
        def __set__(self, value):
            self.ptr.version(small_uint4(<uint8_t> int(value)))

    property type:
        """
        type field (read-write, `4 bits int`)
        """
        def __get__(self):
            return int(<uint8_t> self.ptr.type())
        def __set__(self, value):
            self.ptr.type(small_uint4(<uint8_t> int(value)))

    property code:
        """
        code field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.code())
        def __set__(self, value):
            self.ptr.code(<uint8_t> int(value))

    property session_id:
        """
        session_id field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.session_id())
        def __set__(self, value):
            self.ptr.session_id(<uint16_t> int(value))

    property payload_length:
        """
        the payload_length field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.payload_length())
        def __set__(self, value):
            self.ptr.payload_length(<uint16_t> int(value))

    property service_name:
        """
        service-name tag (read-write, `bytes`)
        """
        def __get__(self):
            try:
                return <bytes> (self.ptr.service_name())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.service_name(<string> (<bytes> value))

    property ac_name:
        """
        AC-name tag (read-write, `bytes`)
        """
        def __get__(self):
            try:
                return <bytes> (self.ptr.ac_name())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.ac_name(<string> (<bytes> value))

    property service_name_error:
        """
        Service-Name-Error tag (read-write, `bytes`)
        """
        def __get__(self):
            try:
                return <bytes> (self.ptr.service_name_error())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.service_name_error(<string> (<bytes> value))

    property ac_system_error:
        """
        AC-System-Error tag (read-write, `bytes`)
        """
        def __get__(self):
            try:
                return <bytes> (self.ptr.ac_system_error())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.ac_system_error(<string> (<bytes> value))

    property generic_error:
        """
        Generic-Error tag (read-write, `bytes`)
        """
        def __get__(self):
            try:
                return <bytes> (self.ptr.generic_error())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            self.ptr.generic_error(<string> (<bytes> value))

    property host_uniq:
        """
        host-uniq tag (read-write, `bytes`)
        """
        def __get__(self):
            cdef vector[uint8_t] v = self.ptr.host_uniq()
            cdef uint8_t* p = &v[0]
            return <bytes> p[:v.size()]
        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* p = <uint8_t*> (<bytes> value)
            cdef vector[uint8_t] v
            v.assign(p, p + len(value))
            self.ptr.host_uniq(v)

    property ac_cookie:
        """
        AC-Cookie tag (read-write, `bytes`)
        """
        def __get__(self):
            cdef vector[uint8_t] v = self.ptr.ac_cookie()
            cdef uint8_t* p = &v[0]
            return <bytes> p[:v.size()]
        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* p = <uint8_t*> (<bytes> value)
            cdef vector[uint8_t] v
            v.assign(p, p + len(value))
            self.ptr.ac_cookie(v)

    property relay_session_id:
        """
        Relay-Session-Id tag (read-write, `bytes`)
        """
        def __get__(self):
            cdef vector[uint8_t] v = self.ptr.relay_session_id()
            cdef uint8_t* p = &v[0]
            return <bytes> p[:v.size()]
        def __set__(self, value):
            value = bytes(value)
            cdef uint8_t* p = <uint8_t*> (<bytes> value)
            cdef vector[uint8_t] v
            v.assign(p, p + len(value))
            self.ptr.relay_session_id(v)

    property tags:
        """
        The list of current tags (read-only)
        """
        def __get__(self):
            returned_tags = []
            cdef cpp_list[pppoe_tag] all_tags = self.ptr.tags()
            cdef pppoe_tag tag
            cdef size_t length
            for tag in all_tags:
                length = tag.data_size()
                returned_tags.append((
                    int(tag.option()),
                    b"" if length == 0 else <bytes> ((tag.data_ptr())[:length])
                ))
            return returned_tags

    cpdef search_tag(self, tag_type):
        """
        search_tag(tag_type)
        Search for a tag by type.

        Parameters
        ----------
        tag_type: :py:class:`~.PPPoE:TagTypes`

        Returns
        -------
        tag: bytes or ``None``
        """
        tag_type = int(tag_type)
        cdef pppoe_tag* tag_ptr = <pppoe_tag*> (self.ptr.search_tag(<PPPoE_TagTypes> tag_type))
        if tag_ptr is NULL:
            return None
        cdef size_t length = int(tag_ptr.data_size())
        if length == 0:
            return b''
        return <bytes> ((tag_ptr.data_ptr())[:length])

    cpdef add_tag(self, tag_type, data=None):
        """
        add_tag(tag_type, data=None)
        Add a tag

        Parameters
        ----------
        tag_type: :py:class:`~.PPPoE:TagTypes`
        data: bytes
        """
        tag_type = int(tag_type)
        cdef pppoe_tag tag
        if data is None:
            tag = pppoe_tag(<PPPoE_TagTypes> tag_type)
        else:
            data = bytes(data)
            tag = pppoe_tag(<PPPoE_TagTypes> tag_type, len(data), <uint8_t*> data)
        self.ptr.add_tag(tag)

    cpdef get_vendor_specific(self):
        """
        get_vendor_specific()

        Returns
        -------
        (vendor_id, data): (uint32_t, bytes)

        Raises
        ------
        exception: :py:class:`~.OptionNotFound`
            if the PDU does not have a Vendor-Specific tag
        """
        cdef pppoe_vendor_spec_type vendor = self.ptr.vendor_specific()
        cdef uint8_t* p = &(vendor.data[0])
        return int(vendor.vendor_id), <bytes> p[:vendor.data.size()]

    cpdef set_vendor_specific(self, vendor_id, data):
        """
        set_vendor_specific(vendor_id, data)
        Add a Vendor-Specific tag

        Parameters
        ----------
        vendor_id: uint32_t
        data: bytes
        """
        vendor_id = int(vendor_id)
        data = bytes(data)
        cdef vector[uint8_t] v
        cdef uint8_t* p = <uint8_t*> (<bytes> data)
        v.assign(p, p + len(data))
        cdef pppoe_vendor_spec_type vendor = pppoe_vendor_spec_type(<uint32_t> vendor_id, v)
        self.ptr.vendor_specific(vendor)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppPPPoE(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppPPPoE*> ptr

PPPOE = PPPoE
