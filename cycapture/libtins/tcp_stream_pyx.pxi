# -*- coding: utf-8 -*-


cdef class TCPStream(object):
    """
    TCP stream encapsulation.

    TCPStream objects are not meant to be made directly by the user. Instead, they are built by libtins and provided
    to TCPStreamFollower callbacks when a TCP stream is updated or closed.

    Attributes
    ----------
    client_addr: :py:class:`~.IPv4Address` or ``None``
        TCP client address
    server_addr: :py:class:`~.IPv4Address` or ``None``
        TCP server address
    client_port: int
        TCP client port
    server_port: int
        TCP server port
    identifier: int
        TCP identifier
    finished: bool
        True if the stream has been closed
    client_payload: bytes
        What has been sent by the client so far
    server_payload: bytes
        What has been sent by the server so far
    """

    def __init__(self, client_addr, server_addr, client_port, server_port, ident, finished, client_payload, server_payload):
        """
        __init__(client_addr, server_addr, client_port, server_port, ident, finished, client_payload, server_payload)
        """

        try:
            if isinstance(client_addr, IPv4Address):
                self.client_addr = client_addr
            else:
                self.client_addr = IPv4Address(client_addr)
        except  (ValueError, TypeError):
            self.client_addr = None

        try:
            if isinstance(server_addr, IPv4Address):
                self.server_addr = server_addr
            else:
                self.server_addr = IPv4Address(server_addr)
        except  (ValueError, TypeError):
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

