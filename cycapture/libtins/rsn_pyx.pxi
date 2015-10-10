# -*- coding: utf-8 -*-

cdef class RSNInformation(object):

    CypherSuites = IntEnum('CypherSuites', {
        'WEP_40': RSN_WEP_40,
        'TKIP': RSN_TKIP,
        'CCMP': RSN_CCMP,
        'WEP_104': RSN_WEP_104
    })

    AKMSuites = IntEnum('AKMSuites', {
        'PMKSA': RSN_PMKSA,
        'PSK': RSN_PSK
    })

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        cdef uint8_t* buf_addr
        cdef uint32_t size
        if buf is None:
            self.ptr = new cppRSNInformation()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppRSNInformation(buf_addr, size)

    def __init__(self, buf=None, _raw=False):
        pass

    def __dealloc__(self):
        if self.ptr is not NULL:
            del self.ptr
        self.ptr = NULL

    cpdef add_pairwise_cypher(self, cypher):
        cypher = int(cypher)
        self.ptr.add_pairwise_cypher(<RSN_CypherSuites> cypher)

    cpdef add_akm_cypher(self, akm):
        akm = int(akm)
        self.ptr.add_akm_cypher(<RSN_AKMSuites> akm)

    property group_suite:
        def __get__(self):
            return int(self.ptr.group_suite())
        def __set__(self, value):
            value = int(value)
            self.ptr.group_suite(<RSN_CypherSuites> value)

    property version:
        def __get__(self):
            return self.ptr.version()
        def __set__(self, value):
            self.ptr.version(<uint16_t> int(value))

    property capabilities:
        def __get__(self):
            return self.ptr.capabilities()
        def __set__(self, value):
            self.ptr.capabilities(<uint16_t> int(value))

    cpdef pairwise_cyphers(self):
        cdef vector[RSN_CypherSuites] v = self.ptr.pairwise_cyphers()
        return [int(suite) for suite in v]

    cpdef akm_cyphers(self):
        cdef vector[RSN_AKMSuites] v = self.ptr.akm_cyphers()
        return [int(suite) for suite in v]

    cpdef serialize(self):
        cdef vector[uint8_t] v = self.ptr.serialize()
        return <bytes>((&v[0])[:v.size()])

