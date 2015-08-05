# -*- coding: utf-8 -*-

cdef extern from "tins/dns.h" namespace "Tins" nogil:
    PDUType dns_pdu_flag "Tins::DNS::pdu_flag"

    cdef cppclass cppDNS "Tins::DNS" (cppPDU):
        pass
