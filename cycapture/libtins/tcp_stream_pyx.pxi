# -*- coding: utf-8 -*-


cdef class TCPStream(object):

    def __init__(self, client_addr, server_addr, client_port, server_port, ident, finished, client_payload, server_payload):

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
                self.server_addr = IPv4Address(server_addr)
        except ValueError:
            self.server_addr = None


        try:
            self.client_port = int(client_port)
        except (ValueError, TypeError):
            self.client_port = -1

        try:
            self.server_port = int(server_port)
        except (ValueError, TypeError):
            self.server_port = -1


        try:
            self.identifier = int(ident)
        except (ValueError, TypeError):
            self.identifier = -1

        self.finished = bool(finished)

        self.client_payload = client_payload
        self.server_payload = server_payload

