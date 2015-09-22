# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from libc.stdint cimport uint16_t, uint32_t, uint8_t, uintptr_t, uint64_t
# noinspection PyUnresolvedReferences
from cpython.ref cimport PyObject
from cpython.ref cimport Py_INCREF


cdef class TCPStream(object):
    def __cinit__(self, client_addr, server_addr, client_port, server_port, ident, finished, client_payload, server_payload):
        try:
            if isinstance(client_addr, IPv4Address):
                self.client_addr = client_addr
            else:
                self.client_addr = IPv4Address(client_addr)
        except ValueError:
            self.client_addr = None

        try:
            if isinstance(server_addr, IPv4Address):
                self.server_addr = server_addr
            else:
                self.server_addr = server_addr(server_addr)
        except ValueError:
            self.server_addr = None

        try:
            self.client_port = int(client_port)
        except ValueError:
            self.client_port = -1

        try:
            self.server_addr = int(server_port)
        except ValueError:
            self.server_port = -1

        try:
            self.identifier = int(ident)
        except ValueError:
            self.identifier = -1

        self.finished = bool(finished)

        self._client_payload = client_payload
        self._server_payload = server_payload

    def __init__(self, client_addr, server_addr, client_port, server_port, ident, finished, client_payload, server_payload):
        pass

    def __dealloc__(self):
        pass


