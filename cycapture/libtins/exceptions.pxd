# noinspection PyUnresolvedReferences
from cpython.ref cimport PyObject


cdef public PyObject* libtins_exception
cdef public PyObject* malformed_address
cdef public PyObject* malformed_packet
cdef public PyObject* malformed_option
cdef public PyObject* option_not_found
cdef public PyObject* option_payload_too_large
cdef public PyObject* field_not_present
cdef public PyObject* pdu_not_found
cdef public PyObject* invalid_interface
cdef public PyObject* unknown_link_type
cdef public PyObject* socket_open_error
cdef public PyObject* socket_close_error
cdef public PyObject* socket_write_error
cdef public PyObject* invalid_socket_type
cdef public PyObject* bad_tins_cast
cdef public PyObject* protocol_disabled



