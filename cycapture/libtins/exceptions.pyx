__author__ = 'stef'

# noinspection PyUnresolvedReferences
from cpython.ref cimport PyObject
import socket


class LibtinsException(StandardError):
    pass
cdef public PyObject* libtins_exception = <PyObject*>LibtinsException

class MalformedAddress(LibtinsException, ValueError):
    pass
cdef public PyObject* malformed_address = <PyObject*>MalformedAddress

class MalformedPacket(LibtinsException, ValueError):
    pass
cdef public PyObject* malformed_packet = <PyObject*>MalformedPacket

class MalformedOption(LibtinsException, ValueError):
    pass
cdef public PyObject* malformed_option = <PyObject*>MalformedOption

class OptionNotFound(LibtinsException, ValueError):
    pass
cdef public PyObject* option_not_found = <PyObject*>OptionNotFound

class OptionPayloadTooLarge(LibtinsException, ValueError):
    pass
cdef public PyObject* option_payload_too_large = <PyObject*>OptionPayloadTooLarge

class FieldNotPresent(LibtinsException, ValueError):
    pass
cdef public PyObject* field_not_present = <PyObject*>FieldNotPresent

class PDUNotFound(LibtinsException):
    pass
cdef public PyObject* pdu_not_found = <PyObject*>PDUNotFound

class InvalidInterface(LibtinsException, IOError):
    pass
cdef public PyObject* invalid_interface = <PyObject*>InvalidInterface

class UnknownLinkType(LibtinsException, IOError):
    pass
cdef public PyObject* unknown_link_type = <PyObject*>UnknownLinkType

class SocketOpenError(LibtinsException, socket.error):
    pass
cdef public PyObject* socket_open_error = <PyObject*>SocketOpenError

class SocketCloseError(LibtinsException, socket.error):
    pass
cdef public PyObject* socket_close_error = <PyObject*>SocketCloseError

class SocketWriteError(LibtinsException, socket.error):
    pass
cdef public PyObject* socket_write_error = <PyObject*>SocketWriteError

class InvalidSocketType(LibtinsException, socket.error):
    pass
cdef public PyObject* invalid_socket_type = <PyObject*>InvalidSocketType

class BadTinsCast(LibtinsException):
    pass
cdef public PyObject* bad_tins_cast = <PyObject*>BadTinsCast

class ProtocolDisabled(LibtinsException):
    pass
cdef public PyObject* protocol_disabled = <PyObject*>ProtocolDisabled




