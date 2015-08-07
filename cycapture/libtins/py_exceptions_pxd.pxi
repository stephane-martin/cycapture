# noinspection PyUnresolvedReferences
from cpython.ref cimport PyObject

cdef public PyObject* py_libtins_exception
cdef public PyObject* py_malformed_address
cdef public PyObject* py_malformed_packet
cdef public PyObject* py_malformed_option
cdef public PyObject* py_option_not_found
cdef public PyObject* py_option_payload_too_large
cdef public PyObject* py_field_not_present
cdef public PyObject* py_pdu_not_found
cdef public PyObject* py_invalid_interface
cdef public PyObject* py_unknown_link_type
cdef public PyObject* py_socket_open_error
cdef public PyObject* py_socket_close_error
cdef public PyObject* py_socket_write_error
cdef public PyObject* py_invalid_socket_type
cdef public PyObject* py_bad_tins_cast
cdef public PyObject* py_protocol_disabled

cdef extern from "custom_exception_handler.h" namespace "Tins":
    cdef void custom_exception_handler()

