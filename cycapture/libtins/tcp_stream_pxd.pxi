# -*- coding: utf-8 -*-

cdef extern from "tins/tcp_stream.h" namespace "Tins" nogil:

    cppclass cppTCPStream "Tins::TCPStream":

        cppclass StreamInfo:
            cppIPv4Address client_addr
            cppIPv4Address server_addr
            uint16_t client_port
            uint16_t server_port
            StreamInfo()
            StreamInfo(cppIPv4Address client, cppIPv4Address server, uint16_t cport, uint16_t sport)

        cppTCPStream(cppIP *ip, cppTCP *tcp, uint64_t identifier)
        cppTCPStream(const cppTCPStream &rhs)
        cppTCPStream& operator=(const cppTCPStream &rhs)
        const vector[uint8_t] &client_payload() const
        vector[uint8_t] &client_payload()
        const vector[uint8_t] &server_payload()
        vector[uint8_t] &server_payload()
        uint64_t ident "id" () const
        const cppTCPStream.StreamInfo &stream_info() const
        cpp_bool is_finished() const
        cpp_bool update(cppIP *ip, cppTCP *tcp)


cdef public class TCPStream(object)[type PyTCPStreamType, object PyTCPStreamObject]:
    cdef readonly IPv4Address client_addr
    cdef readonly IPv4Address server_addr
    cdef readonly int client_port
    cdef readonly int server_port
    cdef readonly uint64_t identifier
    cdef readonly int finished
    cdef object _client_payload
    cdef object _server_payload

