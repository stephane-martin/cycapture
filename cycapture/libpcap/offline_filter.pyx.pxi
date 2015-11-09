# -*- coding: utf-8 -*-

cdef class OfflineFilter(object):
    """
    Offline packet filter: filter packets after they have been captured.
    """

    def __cinit__(self, bytes filter_string, object linktype, int snaplen=65535):
        linktype = _normalize_linktype(linktype)
        if snaplen > 65535 or snaplen <= 0:
            raise ValueError("0 < snaplen <= 65535 is mandatory")
        if filter_string is None:
            raise ValueError("filter_string can't be None")
        if len(filter_string) == 0:
            raise ValueError("filter_string can't be empty")
        self.call_freecode = 0
        self.handle = pcap_open_dead(linktype, snaplen)
        if self.handle == NULL:
            raise RuntimeError("failed pcap_open_dead")

        if pcap_compile(self.handle, &self.program, <const char*> filter_string, 1, PCAP_NETMASK_UNKNOWN) != 0:
            raise PcapException(bytes(pcap_geterr(self.handle)))
        self.call_freecode = 1

    def __dealloc__(self):
        if self.call_freecode:
            pcap_freecode(&self.program)
        if self.handle != NULL:
            pcap_close(self.handle)

    def __init__(self, bytes filter_string, object linktype, int snaplen=65535):
        """
        __init__(filter_string, linktype, snaplen=65535)

        Parameters
        ----------
        filter_string: filter specification
        linktype: the datalink type of the packets to be filtered
        snaplen: the snapshot length of the packets to be filtered
        """

    cdef bint match(self, const uint8_t *pkt, int size) except -1:
        """
        match(const uint8_t *pkt, int size)
        Check whether the given packet matches the filter.

        Parameters
        ----------
        pkt:
            pointer to packet
        size:
            packet size

        Returns
        -------
        match_or_not: bint
        """
        cdef timeval tv
        cdef pcap_pkthdr hdr
        tv.tv_sec = 0
        tv.tv_usec = 0
        hdr.ts = tv
        hdr.caplen = size
        hdr.len = size
        return pcap_offline_filter(&self.program, &hdr, pkt) != 0

    cpdef bint match_pdu(self, object pdu) except -1:
        """
        match_pdu(pdu)
        Check whether the given pdu matches the filter.

        Parameters
        ----------
        pdu: :py:class:`~._tins.PDU`

        Returns
        -------
        match_or_not: bool
        """
        if pdu is None:
            raise ValueError("pdu can't be None")
        serialized = pdu.serialize()
        return self.match(<const uint8_t*> serialized, len(serialized))

    cpdef bint match_buffer(self, object buf) except -1:
        """
        match_buffer(object buf)
        Check whether the given object matches the filter.

        Parameters
        ----------
        buf: bytes or bytearray or memoryview or :py:class:`~._tins.PDU`

        Returns
        -------
        match_or_not: bool
        """
        if buf is None:
            return 0
        if hasattr(buf, 'serialize'):
            return self.match_pdu(buf)
        if isinstance(buf, bytes) or isinstance(buf, bytearray):
            return self.match(<const uint8_t*> buf, len(buf))
        if isinstance(buf, memoryview):
            if buf.itemsize == 1 and buf.ndim == 1:
                return self.match(<const uint8_t*> (mview_get_addr(<void*> buf)), len(buf))
            else:
                raise ValueError("the memoryview doesn't have the proper format")
        if isinstance(buf, cy_memoryview):
            if buf.itemsize == 1 and buf.ndim == 1:
                return self.match(<const uint8_t*> (<cy_memoryview>buf).get_item_pointer([]), len(buf))
            else:
                raise ValueError("the typed memoryview doesn't have the proper format")
        raise TypeError("don't know what do to with type: '%s'" % type(buf))

    def ifilter(self, list_of_bufs_or_pdus):
        """
        Return those items of sequence for which the filter matches.

        Parameters
        ----------
        list_of_bufs_or_pdus: sequence of `PDUs or buffers`
        """
        for buf in list_of_bufs_or_pdus:
            try:
                if self.match_buffer(buf):
                    yield buf
            except (TypeError, ValueError) as ex:
                pass
