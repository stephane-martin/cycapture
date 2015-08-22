# -*- coding: utf-8 -*-

cdef extern from "tins/utils.h" namespace "Tins::Utils" nogil:
    ctypedef struct cppRouteEntry "Tins::Utils::RouteEntry":
        string interface
        cppIPv4Address destination
        cppIPv4Address gateway
        cppIPv4Address mask
    cppIPv4Address resolve_domain(const string &to_resolve)
    cpp_set[string] cpp_network_interfaces "Tins::Utils::network_interfaces"()
    cpp_bool gateway_from_ip(cppIPv4Address ip, cppIPv4Address &gw_addr)
    vector[cppRouteEntry] route_entries()
    uint32_t crc32(const uint8_t* data, uint32_t data_size)
    uint16_t channel_to_mhz(uint16_t channel)
    uint16_t mhz_to_channel(uint16_t mhz)
    string cpp_pdutype_to_string "Tins::Utils::to_string" (PDUType pduType)
    uint32_t do_checksum(const uint8_t *start, const uint8_t *end)
    uint32_t pseudoheader_checksum(cppIPv4Address source_ip, cppIPv4Address dest_ip, uint32_t len, uint32_t flag)


cdef class RouteEntry(object):
    cdef readonly bytes interface
    cdef readonly IPv4Address destination
    cdef readonly IPv4Address gateway
    cdef readonly IPv4Address mask

cpdef get_route_entries()
cpdef list_network_interfaces()
cpdef pdutype_to_string(int t)
