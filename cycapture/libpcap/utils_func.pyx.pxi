# -*- coding: utf-8 -*-

cpdef object lookupdev():
    """
    lookupdev()
    Returns the default interface.

    Returns
    -------
    interface: bytes
        default interface to sniff on
    """
    cdef char* name
    cdef char err_buf[PCAP_ERRBUF_SIZE]
    name = pcap_lookupdev(err_buf)
    if name == NULL:
        raise PcapException(<bytes> err_buf)
    return <bytes>name

cdef bytes int_to_address(int i):
    return b'.'.join([bytes(ord(c)) for c in struct_module.pack('I', i)])


cpdef object lookupnet(device):
    """
    lookupnet(device)
    Find the IPv4 network number and netmask for a device.

    Parameters
    ----------
    device: bytes or :py:class:`~.NetworkInterface`
        interface name

    Returns
    -------
    (netp, maskp, ipv4_netp, ipv4_maskp): int, int, bytes, bytes
    """
    device = bytes(device)
    cdef unsigned int netp
    cdef unsigned int maskp
    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef int res
    res = pcap_lookupnet(<char*> device, &netp, &maskp, errbuf)
    if res == 0:
        return int(netp), int(maskp), int_to_address(netp), int_to_address(maskp)
    else:
        raise PcapExceptionFactory(res, <bytes> errbuf)


cpdef object datalink_to_description(int dlt):
    """
    datalink_to_description(int dlt)

    Parameters
    ----------
    dlt

    Returns
    -------
    (name, description): bytes, bytes
        the name and description corresponding to the numeric `dlt`
    """

    cdef const char* name = pcap_datalink_val_to_name(dlt)
    cdef const char* description = pcap_datalink_val_to_description(dlt)
    cdef bytes name_b = b''
    cdef bytes description_b = b''
    if name != NULL:
        name_b = bytes(name)
    if description != NULL:
        description_b = bytes(description)
    return name_b, description_b
