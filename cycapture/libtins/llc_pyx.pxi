# -*- coding: utf-8 -*-

cdef class LLC(PDU):
    pdu_flag = PDU.LLC
    pdu_type = PDU.LLC

    Format = IntEnum('Format', {
        "INFORMATION": LLC_INFORMATION,
        "SUPERVISORY": LLC_SUPERVISORY,
        "UNNUMBERED": LLC_UNNUMBERED
    })

    ModifierFunctions = IntEnum('ModifierFunctions', {
        "UI": LLC_UI,
        "XID": LLC_XID,
        "TEST": LLC_TEST,
        "SABME": LLC_SABME,
        "DISC": LLC_DISC,
        "UA": LLC_UA,
        "DM": LLC_DM,
        "FRMR": LLC_FRMR
    })

    SupervisoryFunctions = IntEnum('SupervisoryFunctions', {
        "RECEIVE_READY": LLC_RECEIVE_READY,
        "REJECT": LLC_REJECT,
        "RECEIVE_NOT_READY": LLC_RECEIVE_NOT_READY
    })

    def __cinit__(self, dsap=0, ssap=0, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != LLC:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppLLC(<uint8_t> int(dsap), <uint8_t> int(ssap))
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppLLC(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppLLC* p = <cppLLC*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dsap=0, ssap=0, buf=None, _raw=False):
        pass

    cpdef clear_information_fields(self):
        self.ptr.clear_information_fields()

    property group:
        def __get__(self):
            return bool(self.ptr.group())
        def __set__(self, value):
            value = bool(value)
            self.ptr.group(<cpp_bool> value)

    property dsap:
        def __get__(self):
            return int(self.ptr.dsap())
        def __set__(self, value):
            self.ptr.dsap(<uint8_t> int(value))

    property response:
        def __get__(self):
            return bool(self.ptr.response())
        def __set__(self, value):
            value = bool(value)
            self.ptr.response(<cpp_bool> value)

    property ssap:
        def __get__(self):
            return int(self.ptr.ssap())
        def __set__(self, value):
            self.ptr.ssap(<uint8_t> int(value))

    property type:
        def __get__(self):
            return int(self.ptr.type())
        def __set__(self, value):
            if isinstance(value, LLC.Format):
                value = value.value
            value = int(value)
            self.ptr.type(<LLC_Format> value)

    property send_seq_number:
        def __get__(self):
            return int(self.ptr.send_seq_number())
        def __set__(self, value):
            self.ptr.send_seq_number(<uint8_t> int(value))

    property receive_seq_number:
        def __get__(self):
            return int(self.ptr.receive_seq_number())
        def __set__(self, value):
            self.ptr.receive_seq_number(<uint8_t> int(value))

    property poll_final:
        def __get__(self):
            return bool(self.ptr.poll_final())
        def __set__(self, value):
            value = bool(value)
            self.ptr.poll_final(<cpp_bool> value)

    property supervisory_function:
        def __get__(self):
            return int(self.ptr.supervisory_function())
        def __set__(self, value):
            if isinstance(value, LLC.SupervisoryFunctions):
                value = value.value
            value = int(value)
            self.ptr.supervisory_function(<LLC_SupervisoryFunctions> value)

    property modifier_function:
        def __get__(self):
            return int(self.ptr.modifier_function())
        def __set__(self, value):
            if isinstance(value, LLC.ModifierFunctions):
                value = value.value
            value = int(value)
            self.ptr.modifier_function(<LLC_ModifierFunctions> value)

