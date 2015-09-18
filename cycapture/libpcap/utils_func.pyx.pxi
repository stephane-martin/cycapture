

cpdef object lookupdev():
    cdef char* name
    cdef char err_buf[PCAP_ERRBUF_SIZE]
    name = pcap_lookupdev(err_buf)
    if name == NULL:
        raise PcapException(<bytes> err_buf)
    return <bytes>name

cdef object sockaddress_to_bytes(const sockaddr* sa):
    if sa == NULL:
        return b'', b''
    if sa.sa_family not in (AF_INET, AF_INET6, AF_LINK):
        return b'unknown: {}'.format(sa.sa_family), b''
    cdef int res
    cdef char hbuf[NI_MAXHOST]
    cdef char hbuf4[INET_ADDRSTRLEN]
    cdef char hbuf6[INET6_ADDRSTRLEN]
    cdef sockaddr_in* concrete4
    cdef sockaddr_in6* concrete6
    if sa.sa_family == AF_INET6:
        concrete6 = <sockaddr_in6*> sa
        if getnameinfo(sa, sizeof(concrete6[0]), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0:
            return b'ipv6', <bytes> hbuf
        return b'ipv6', b''
    elif sa.sa_family == AF_INET:
        concrete4 = <sockaddr_in*> sa
        if getnameinfo(sa, sizeof(concrete4[0]), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0:
            return b'ipv4', <bytes> hbuf
        return b'ipv4', b''
    elif sa.sa_family == AF_LINK:
        # noinspection PyUnresolvedReferences
        IF UNAME_SYSNAME == "Darwin":
            if getnameinfo(sa, sa.sa_len, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0:
                return b'link', <bytes> hbuf
            return b'link', b''
        ELSE:
            return b'link', b''


cpdef object findalldevs():
    cdef int res
    cdef pcap_if_t* all_interfaces
    cdef pcap_if_t* first_interface
    cdef pcap_addr_t* current_address

    interfaces = []
    cdef char err_buf[PCAP_ERRBUF_SIZE]
    res = pcap_findalldevs(&all_interfaces, err_buf)
    if res < 0:
        raise PcapExceptionFactory(res, <bytes> err_buf)

    first_interface = all_interfaces
    while all_interfaces != NULL:
        name = <bytes> all_interfaces.name
        description = b''
        if all_interfaces.description != NULL:
            description = <bytes> all_interfaces.description
        interface = {'name': name, 'description': description, 'addresses': [], 'flags': <int> all_interfaces.flags}
        current_address = all_interfaces.addresses
        while current_address != NULL:
            interface['addresses'].append(
                {
                    'addr': sockaddress_to_bytes(current_address.addr),
                    'netmask': sockaddress_to_bytes(current_address.netmask),
                    'dstaddr': sockaddress_to_bytes(current_address.dstaddr),
                    'broadaddr': sockaddress_to_bytes(current_address.broadaddr)
                }
            )
            current_address = current_address.next
        interfaces.append(interface)
        all_interfaces = all_interfaces.next
    pcap_freealldevs(first_interface)
    return interfaces


cdef bytes int_to_address(int i):
    return b'.'.join([bytes(ord(c)) for c in struct_module.pack('I', i)])


cpdef object lookupnet(bytes device):
    cdef unsigned int netp
    cdef unsigned int maskp
    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef int res
    res = pcap_lookupnet(<char*> device, &netp, &maskp, errbuf)
    if res == 0:
        return int(netp), int(maskp), int_to_address(netp), int_to_address(maskp)
    else:
        raise PcapExceptionFactory(res, <bytes> errbuf)


cpdef object datalink_val_to_name_description(int dlt):
    cdef const char* name = pcap_datalink_val_to_name(dlt)
    cdef const char* description = pcap_datalink_val_to_description(dlt)
    cdef bytes name_b = b''
    cdef bytes description_b = b''
    if name != NULL:
        name_b = bytes(name)
    if description != NULL:
        description_b = bytes(description)
    return name_b, description_b
