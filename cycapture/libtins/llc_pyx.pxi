# -*- coding: utf-8 -*-

cdef class LLC(PDU):
    """
    LLC frame (IEEE 802.2)
    """
    pdu_flag = PDU.LLC
    pdu_type = PDU.LLC

    Format = make_enum('LLC_Format', 'Format', 'LLC Format flags', {
        "INFORMATION": LLC_INFORMATION,
        "SUPERVISORY": LLC_SUPERVISORY,
        "UNNUMBERED": LLC_UNNUMBERED
    })

    ModifierFunctions = make_enum('LLC_ModifierFunctions', 'ModifierFunctions', 'LLC Modifier functions', {
        "UI": LLC_UI,
        "XID": LLC_XID,
        "TEST": LLC_TEST,
        "SABME": LLC_SABME,
        "DISC": LLC_DISC,
        "UA": LLC_UA,
        "DM": LLC_DM,
        "FRMR": LLC_FRMR
    })

    SupervisoryFunctions = make_enum('LLC_SupervisoryFunctions', 'SupervisoryFunctions', 'LLC Supervisory functions', {
        "RECEIVE_READY": LLC_RECEIVE_READY,
        "REJECT": LLC_REJECT,
        "RECEIVE_NOT_READY": LLC_RECEIVE_NOT_READY
    })

    def __cinit__(self, dsap=0, ssap=0, _raw=False):
        if _raw is True or type(self) != LLC:
            return

        self.ptr = new cppLLC(<uint8_t> int(dsap), <uint8_t> int(ssap))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppLLC* p = <cppLLC*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dsap=0, ssap=0):
        """
        __init__(dsap=0, ssap=0)
        Constructs an instance of LLC, setting the dsap and ssap.

        The control field is set to 0.

        Parameters
        ----------
        dsap: int
            The dsap value
        ssap: int
            The ssap value
        """

    cpdef clear_information_fields(self):
        self.ptr.clear_information_fields()

    property group:
        """
        group destination bit (read-write, `bool`)
        """
        def __get__(self):
            return bool(self.ptr.group())
        def __set__(self, value):
            value = bool(value)
            self.ptr.group(<cpp_bool> value)

    property dsap:
        """
        dsap field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.dsap())
        def __set__(self, value):
            self.ptr.dsap(<uint8_t> int(value))

    property response:
        """
        response bit (read-write, `bool`)
        """
        def __get__(self):
            return bool(self.ptr.response())
        def __set__(self, value):
            value = bool(value)
            self.ptr.response(<cpp_bool> value)

    property ssap:
        """
        ssap field (read-write, `uint8_t`)
        """
        def __get__(self):
            return int(self.ptr.ssap())
        def __set__(self, value):
            self.ptr.ssap(<uint8_t> int(value))

    property type:
        """
        LLC frame format type (read-write, :py:class:`~.LLC.Format`)
        """
        def __get__(self):
            return int(self.ptr.type())
        def __set__(self, value):
            if isinstance(value, LLC.Format):
                value = value.value
            value = int(value)
            self.ptr.type(<LLC_Format> value)

    property send_seq_number:
        """
        sender send sequence number (read-write, `uint8_t`; only applied if format is INFORMATION)
        """
        def __get__(self):
            return int(self.ptr.send_seq_number())
        def __set__(self, value):
            self.ptr.send_seq_number(<uint8_t> int(value))

    property receive_seq_number:
        """
        sender receive sequence number (read-write, `uint8_t`; only applied if format is INFORMATION or SUPERVISORY)
        """
        def __get__(self):
            return int(self.ptr.receive_seq_number())
        def __set__(self, value):
            self.ptr.receive_seq_number(<uint8_t> int(value))

    property poll_final:
        """
        poll/final flag (read-write, `bool`)
        """
        def __get__(self):
            return bool(self.ptr.poll_final())
        def __set__(self, value):
            value = bool(value)
            self.ptr.poll_final(<cpp_bool> value)

    property supervisory_function:
        """
        supervisory function (read-write, :py:class:`~.LLC.SupervisoryFunctions`; only applied if format is SUPERVISORY)
        """
        def __get__(self):
            return int(self.ptr.supervisory_function())
        def __set__(self, value):
            if isinstance(value, LLC.SupervisoryFunctions):
                value = value.value
            value = int(value)
            self.ptr.supervisory_function(<LLC_SupervisoryFunctions> value)

    property modifier_function:
        """
        modifier function field (read-write, :py:class:`~.LLC.ModifierFunctions`; only applied if format is UNNUMBERED)
        """
        def __get__(self):
            return int(self.ptr.modifier_function())
        def __set__(self, value):
            if isinstance(value, LLC.ModifierFunctions):
                value = value.value
            value = int(value)
            self.ptr.modifier_function(<LLC_ModifierFunctions> value)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppLLC(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppLLC*> ptr
