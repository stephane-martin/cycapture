# -*- coding: utf-8 -*-

cdef class RSNInformation(object):
    """
    The RSN information structure
    """

    CypherSuites = make_enum('RSN_CypherSuites', 'CypherSuites', 'the different cypher suites', {
        'WEP_40': RSN_WEP_40,
        'TKIP': RSN_TKIP,
        'CCMP': RSN_CCMP,
        'WEP_104': RSN_WEP_104
    })

    AKMSuites = make_enum('RSN_AKMSuites', 'AKMSuites', 'the different akm suites', {
        'PMKSA': RSN_PMKSA,
        'PSK': RSN_PSK
    })

    def __cinit__(self, _raw=False):
        if _raw is True:
            return
        self.ptr = new cppRSNInformation()

    def __init__(self):
        """
        __init__()

        The version is set to 1.
        """

    def __dealloc__(self):
        if self.ptr is not NULL:
            del self.ptr
        self.ptr = NULL

    cpdef add_pairwise_cypher(self, cypher):
        """
        add_pairwise_cypher(cypher)
        Add a pairwise cypher suite

        Parameters
        ----------
        cypher: :py:class:`~.RSNInformation.CypherSuites`
            The pairwise cypher suite
        """
        cypher = int(cypher)
        self.ptr.add_pairwise_cypher(<RSN_CypherSuites> cypher)

    cpdef add_akm_cypher(self, akm):
        """
        add_akm_cypher(akm)
        Add an akm suite

        Parameters
        ----------
        akm: :py:class:`~.RSNInformation.AKMSuites`
            The akm suite

        """
        akm = int(akm)
        self.ptr.add_akm_cypher(<RSN_AKMSuites> akm)

    property group_suite:
        """
        group suite cypher field (read-write, :py:class:`~.RSNInformation.CypherSuites`)
        """
        def __get__(self):
            return int(self.ptr.group_suite())
        def __set__(self, value):
            value = int(value)
            self.ptr.group_suite(<RSN_CypherSuites> value)

    property version:
        """
        Version field (read-write, `uint16_t`)
        """
        def __get__(self):
            return self.ptr.version()
        def __set__(self, value):
            self.ptr.version(<uint16_t> int(value))

    property capabilities:
        """
        capabilities field (read-write, `uint16_t`)
        """
        def __get__(self):
            return self.ptr.capabilities()
        def __set__(self, value):
            self.ptr.capabilities(<uint16_t> int(value))

    cpdef get_pairwise_cyphers(self):
        """
        get_pairwise_cyphers()
        Returns the pairwise cypher suite list.

        Returns
        -------
        suites: list of :py:class:`~.RSNInformation.CypherSuites`
        """
        cdef vector[RSN_CypherSuites] v = self.ptr.pairwise_cyphers()
        return [int(suite) for suite in v]

    cpdef get_akm_cyphers(self):
        """
        get_pairwise_cyphers()
        Returns the akm suite list.

        Returns
        -------
        suites: list of :py:class:`~.RSNInformation.AKMSuites`
        """
        cdef vector[RSN_AKMSuites] v = self.ptr.akm_cyphers()
        return [int(suite) for suite in v]

    cpdef serialize(self):
        """
        Serialize the object.

        Returns
        -------
        s: bytes
        """
        cdef vector[uint8_t] v = self.ptr.serialize()
        return <bytes>((&v[0])[:v.size()])

    @staticmethod
    cdef factory(cppRSNInformation* info):
        obj = RSNInformation.__new__(RSNInformation, _raw=True)
        (<RSNInformation> obj).ptr = new cppRSNInformation()
        (<RSNInformation> obj).ptr[0] = info[0]
        return obj

    @staticmethod
    def from_buffer(buf):
        """
        Constructs an RSNInformation object

        Parameters
        ----------
        buf: bytes or bytearray or memoryview

        Returns
        -------
        obj: :py:class:`~.RSNInformation`
        """
        obj = RSNInformation.__new__(RSNInformation, _raw=True)
        cdef uint8_t* buf_addr
        cdef uint32_t size
        PDU.prepare_buf_arg(buf, &buf_addr, &size)
        (<RSNInformation> obj).ptr = new cppRSNInformation(buf_addr, size)
        return obj
