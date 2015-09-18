# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from cpython.ref cimport PyObject
import socket


class LibtinsException(Exception):
    """
    Base exception class used by the cycapture.libtins bindings.
    """
cdef public PyObject* py_libtins_exception = <PyObject*>LibtinsException

class MalformedAddress(LibtinsException, ValueError):
    pass
cdef public PyObject* py_malformed_address = <PyObject*>MalformedAddress

class MalformedPacket(LibtinsException, ValueError):
    """
    Exception thrown when a malformed packet is parsed.
    """
cdef public PyObject* py_malformed_packet = <PyObject*>MalformedPacket

class MalformedOption(LibtinsException, ValueError):
    """
    Exception thrown when a malformed option is found.
    """
cdef public PyObject* py_malformed_option = <PyObject*>MalformedOption

class OptionNotFound(LibtinsException, ValueError):
    """
    Exception thrown when an option is not found.
    """
cdef public PyObject* py_option_not_found = <PyObject*>OptionNotFound

class OptionPayloadTooLarge(LibtinsException, ValueError):
    """
    Exception thrown when a payload is too large to fit into a PDU option
    """
cdef public PyObject* py_option_payload_too_large = <PyObject*>OptionPayloadTooLarge

class FieldNotPresent(LibtinsException, ValueError):
    """
    Exception thrown when a field is not present in frame.
    """
cdef public PyObject* py_field_not_present = <PyObject*>FieldNotPresent

class PDUNotFound(LibtinsException):
    """
    Exception thrown when a PDU is not found.
    """
cdef public PyObject* py_pdu_not_found = <PyObject*>PDUNotFound

class InvalidInterface(LibtinsException, IOError):
    """
    Exception thrown when `send` requires a valid interface, but an invalid is used.
    """
cdef public PyObject* py_invalid_interface = <PyObject*>InvalidInterface

class UnknownLinkType(LibtinsException, IOError):
    """
    Exception thrown when an unkown link layer PDU type is found while sniffing.
    """
cdef public PyObject* py_unknown_link_type = <PyObject*>UnknownLinkType

class SocketOpenError(LibtinsException, socket.error):
    """
    Exception thrown when PacketSender fails to open a socket.
    """
cdef public PyObject* py_socket_open_error = <PyObject*>SocketOpenError

class SocketCloseError(LibtinsException, socket.error):
    """
    Exception thrown when PacketSender fails to close a socket.
    """
cdef public PyObject* py_socket_close_error = <PyObject*>SocketCloseError

class SocketWriteError(LibtinsException, socket.error):
    """
    Exception thrown when PacketSender fails to write on a socket
    """
cdef public PyObject* py_socket_write_error = <PyObject*>SocketWriteError

class InvalidSocketType(LibtinsException, socket.error):
    """
    Exception thrown when an invalid socket type is provided to PacketSender.
    """
cdef public PyObject* py_invalid_socket_type = <PyObject*>InvalidSocketType

class BadTinsCast(LibtinsException):
    """
    Exception thrown when a call to tins_cast fails.
    """
cdef public PyObject* py_bad_tins_cast = <PyObject*>BadTinsCast

class ProtocolDisabled(LibtinsException):
    """
    Exception thrown when sniffing a protocol that has been disabled at libtins compile time.
    """
cdef public PyObject* py_protocol_disabled = <PyObject*>ProtocolDisabled

class MemoryViewFormat(LibtinsException, ValueError):
    pass
