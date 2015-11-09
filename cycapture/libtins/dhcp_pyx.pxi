# -*- coding: utf-8 -*-

cdef class DHCP(BootP):
    """
    DHCP packet

    Note
    ----
    When adding options, the `End` option is not added automatically, so you should add it yourself.
    """
    pdu_flag = PDU.DHCP
    pdu_type = PDU.DHCP

    Flags = make_enum('DHCP_Flags', 'Flags', 'DHCP flags', {
        'DISCOVER':     DHCP_DISCOVER ,
        'OFFER':        DHCP_OFFER,
        'REQUEST':      DHCP_REQUEST,
        'DECLINE':      DHCP_DECLINE,
        'ACK':          DHCP_ACK,
        'NAK':          DHCP_NAK,
        'RELEASE':      DHCP_RELEASE,
        'INFORM':       DHCP_INFORM
    })

    OptionTypes = make_enum('DHCP_OptionTypes', 'OptionTypes', 'DHCP options', {
        'PAD': DHCP_PAD,
        'SUBNET_MASK': DHCP_SUBNET_MASK,
        'TIME_OFFSET': DHCP_TIME_OFFSET,
        'ROUTERS': DHCP_ROUTERS,
        'TIME_SERVERS': DHCP_TIME_SERVERS,
        'NAME_SERVERS': DHCP_NAME_SERVERS,
        'DOMAIN_NAME_SERVERS': DHCP_DOMAIN_NAME_SERVERS,
        'LOG_SERVERS': DHCP_LOG_SERVERS,
        'COOKIE_SERVERS': DHCP_COOKIE_SERVERS,
        'LPR_SERVERS': DHCP_LPR_SERVERS,
        'IMPRESS_SERVERS': DHCP_IMPRESS_SERVERS,
        'RESOURCE_LOCATION_SERVERS': DHCP_RESOURCE_LOCATION_SERVERS,
        'HOST_NAME': DHCP_HOST_NAME,
        'BOOT_SIZE': DHCP_BOOT_SIZE,
        'MERIT_DUMP': DHCP_MERIT_DUMP,
        'DOMAIN_NAME': DHCP_DOMAIN_NAME,
        'SWAP_SERVER': DHCP_SWAP_SERVER,
        'ROOT_PATH': DHCP_ROOT_PATH,
        'EXTENSIONS_PATH': DHCP_EXTENSIONS_PATH ,
        'IP_FORWARDING': DHCP_IP_FORWARDING,
        'NON_LOCAL_SOURCE_ROUTING': DHCP_NON_LOCAL_SOURCE_ROUTING,
        'POLICY_FILTER': DHCP_POLICY_FILTER,
        'MAX_DGRAM_REASSEMBLY': DHCP_MAX_DGRAM_REASSEMBLY,
        'DEFAULT_IP_TTL': DHCP_DEFAULT_IP_TTL,
        'PATH_MTU_AGING_TIMEOUT': DHCP_PATH_MTU_AGING_TIMEOUT,
        'PATH_MTU_PLATEAU_TABLE': DHCP_PATH_MTU_PLATEAU_TABLE,
        'INTERFACE_MTU': DHCP_INTERFACE_MTU,
        'ALL_SUBNETS_LOCAL': DHCP_ALL_SUBNETS_LOCAL,
        'BROADCAST_ADDRESS': DHCP_BROADCAST_ADDRESS,
        'PERFORM_MASK_DISCOVERY': DHCP_PERFORM_MASK_DISCOVERY,
        'MASK_SUPPLIER': DHCP_MASK_SUPPLIER,
        'ROUTER_DISCOVERY': DHCP_ROUTER_DISCOVERY,
        'ROUTER_SOLICITATION_ADDRESS': DHCP_ROUTER_SOLICITATION_ADDRESS,
        'STATIC_ROUTES': DHCP_STATIC_ROUTES,
        'TRAILER_ENCAPSULATION': DHCP_TRAILER_ENCAPSULATION,
        'ARP_CACHE_TIMEOUT': DHCP_ARP_CACHE_TIMEOUT,
        'IEEE802_3_ENCAPSULATION': DHCP_IEEE802_3_ENCAPSULATION,
        'DEFAULT_TCP_TTL': DHCP_DEFAULT_TCP_TTL,
        'TCP_KEEPALIVE_INTERVAL': DHCP_TCP_KEEPALIVE_INTERVAL,
        'TCP_KEEPALIVE_GARBAGE': DHCP_TCP_KEEPALIVE_GARBAGE,
        'NIS_DOMAIN': DHCP_NIS_DOMAIN,
        'NIS_SERVERS': DHCP_NIS_SERVERS,
        'NTP_SERVERS': DHCP_NTP_SERVERS,
        'VENDOR_ENCAPSULATED_OPTIONS': DHCP_VENDOR_ENCAPSULATED_OPTIONS,
        'NETBIOS_NAME_SERVERS': DHCP_NETBIOS_NAME_SERVERS,
        'NETBIOS_DD_SERVER': DHCP_NETBIOS_DD_SERVER,
        'NETBIOS_NODE_TYPE': DHCP_NETBIOS_NODE_TYPE,
        'NETBIOS_SCOPE': DHCP_NETBIOS_SCOPE,
        'FONT_SERVERS': DHCP_FONT_SERVERS,
        'X_DISPLAY_MANAGER': DHCP_X_DISPLAY_MANAGER,
        'DHCP_REQUESTED_ADDRESS': DHCP_DHCP_REQUESTED_ADDRESS,
        'DHCP_LEASE_TIME': DHCP_DHCP_LEASE_TIME,
        'DHCP_OPTION_OVERLOAD': DHCP_DHCP_OPTION_OVERLOAD,
        'DHCP_MESSAGE_TYPE': DHCP_DHCP_MESSAGE_TYPE,
        'DHCP_SERVER_IDENTIFIER': DHCP_DHCP_SERVER_IDENTIFIER,
        'DHCP_PARAMETER_REQUEST_LIST': DHCP_DHCP_PARAMETER_REQUEST_LIST,
        'DHCP_MESSAGE': DHCP_DHCP_MESSAGE,
        'DHCP_MAX_MESSAGE_SIZE': DHCP_DHCP_MAX_MESSAGE_SIZE,
        'DHCP_RENEWAL_TIME': DHCP_DHCP_RENEWAL_TIME,
        'DHCP_REBINDING_TIME': DHCP_DHCP_REBINDING_TIME,
        'VENDOR_CLASS_IDENTIFIER': DHCP_VENDOR_CLASS_IDENTIFIER,
        'DHCP_CLIENT_IDENTIFIER': DHCP_DHCP_CLIENT_IDENTIFIER,
        'NWIP_DOMAIN_NAME': DHCP_NWIP_DOMAIN_NAME,
        'NWIP_SUBOPTIONS': DHCP_NWIP_SUBOPTIONS,
        'USER_CLASS': DHCP_USER_CLASS,
        'FQDN': DHCP_FQDN,
        'DHCP_AGENT_OPTIONS': DHCP_DHCP_AGENT_OPTIONS,
        'SUBNET_SELECTION': DHCP_SUBNET_SELECTION,
        'AUTHENTICATE': DHCP_AUTHENTICATE,
        'END': DHCP_END
    })

    def __cinit__(self, _raw=False):
        if _raw is True or type(self) != DHCP:
            return

        self.ptr = new cppDHCP()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDHCP* p = <cppDHCP*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self):
        """
        __init__()
        """

    property type:
        """
        DHCP type option (read-write, :py:class:`~.DHCP.Flags`)
        """
        def __get__(self):
            try:
                return int((<cppDHCP*> self.ptr).type())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = int(value)
            (<cppDHCP*> self.ptr).type(<DHCP_Flags> value)

    cpdef end(self):
        """
        end()
        Adds an end option to the option list.

        The END option is not added automatically. You should explicitly
        add it at the end of the DHCP options to be standard-compliant.
        """
        (<cppDHCP*> self.ptr).end()

    property server_identifier:
        """
        Server identifier option (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            try:
                return IPv4Address((<cppDHCP*> self.ptr).server_identifier().to_string())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = IPv4Address(value)
            (<cppDHCP*> self.ptr).server_identifier((<IPv4Address> value).ptr[0])

    property lease_time:
        """
        Lease time option (read-write, `uint32_t`)
        """
        def __get__(self):
            try:
                return int((<cppDHCP*> self.ptr).lease_time())
            except OptionNotFound:
                return None
        def __set__(self, value):
            (<cppDHCP*> self.ptr).lease_time(<uint32_t> int(value))

    property renewal_time:
        """
        Renewal time option (read-write, `uint32_t`)
        """
        def __get__(self):
            try:
                return int((<cppDHCP*> self.ptr).renewal_time())
            except OptionNotFound:
                return None
        def __set__(self, value):
            (<cppDHCP*> self.ptr).renewal_time(<uint32_t> int(value))

    property rebind_time:
        """
        Rebind time option (read-write, `uint32_t`)
        """

        def __get__(self):
            try:
                return int((<cppDHCP*> self.ptr).rebind_time())
            except OptionNotFound:
                return None
        def __set__(self, value):
            (<cppDHCP*> self.ptr).rebind_time(<uint32_t> int(value))

    property subnet_mask:
        """
        Subnet mask option (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            try:
                return IPv4Address((<cppDHCP*> self.ptr).subnet_mask().to_string())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = IPv4Address(value)
            (<cppDHCP*> self.ptr).subnet_mask((<IPv4Address> value).ptr[0])

    property routers:
        """
        Routers option (read-write, list of :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            cdef vector[cppIPv4Address] v
            try:
                v = (<cppDHCP*> self.ptr).routers()
                return [IPv4Address(cpp_addr.to_string()) for cpp_addr in v]
            except OptionNotFound:
                return None
        def __set__(self, value):
            cdef vector[cppIPv4Address] v
            for addr in value:
                v.push_back(IPv4Address(addr).ptr[0])
            (<cppDHCP*> self.ptr).routers(v)

    property domain_name_servers:
        """
        Domain name servers option (read-write, list of :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            cdef vector[cppIPv4Address] v
            try:
                v = (<cppDHCP*> self.ptr).domain_name_servers()
                return [IPv4Address(cpp_addr.to_string()) for cpp_addr in v]
            except OptionNotFound:
                return None
        def __set__(self, value):
            cdef vector[cppIPv4Address] v
            for addr in value:
                v.push_back(IPv4Address(addr).ptr[0])
            (<cppDHCP*> self.ptr).domain_name_servers(v)

    property broadcast:
        """
        Broadcast option (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            try:
                return IPv4Address((<cppDHCP*> self.ptr).broadcast().to_string())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = IPv4Address(value)
            (<cppDHCP*> self.ptr).broadcast((<IPv4Address> value).ptr[0])

    property requested_ip:
        """
        Requested IP option (read-write, :py:class:`~.IPv4Address`)
        """
        def __get__(self):
            try:
                return IPv4Address((<cppDHCP*> self.ptr).requested_ip().to_string())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = IPv4Address(value)
            (<cppDHCP*> self.ptr).requested_ip((<IPv4Address> value).ptr[0])

    property domain_name:
        """
        Domain name option (read-write, `bytes`)
        """
        def __get__(self):
            try:
                return <bytes> ((<cppDHCP*> self.ptr).domain_name())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            (<cppDHCP*> self.ptr).domain_name(<string> value)

    property hostname:
        """
        Hostname option (read-write, `bytes`)
        """
        def __get__(self):
            try:
                return <bytes> ((<cppDHCP*> self.ptr).hostname())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = bytes(value)
            (<cppDHCP*> self.ptr).hostname(<string> value)

    cpdef add_option(self, identifier, data=None):
        """
        add_option(identifier, data=None)
        Add an option

        Parameters
        ----------
        identifier: :py:class:`~.DHCP.OptionTypes`
            option type
        data: ``None`` or `bytes`
            option data
        """
        cdef dhcp_option opt
        identifier = int(identifier)
        if data is None:
            opt = dhcp_option(<uint8_t> identifier)
        else:
            data = bytes(data)
            opt = dhcp_option(<uint8_t> identifier, len(data), <uint8_t*> data)
        (<cppDHCP*> self.ptr).add_option(opt)

    cpdef search_option(self, identifier):
        """
        search_option(identifier)
        Search for an option by type

        Parameters
        ----------
        identifier: :py:class:`~.DHCP.OptionTypes`

        Returns
        -------
        data: ``None`` (option is not present) or ``b''`` (option is present, no data) or some `bytes` (option data)
        """
        identifier = int(identifier)
        cdef dhcp_option* opt = <dhcp_option*> ((<cppDHCP*> self.ptr).search_option(<DHCP_OptionTypes> identifier))
        if opt is NULL:
            return None
        cdef int length = opt.data_size()
        if not length:
            return b''
        return <bytes> ((opt.data_ptr())[:length])

    cpdef options(self):
        """
        options()
        Returns the list of current options.

        Returns
        -------
        options: list of 2-uple (option type `int`, data `bytes`)
        """
        cdef cpp_list[dhcp_option] opts = (<cppDHCP*> self.ptr).options()
        cdef dhcp_option opt
        results = []
        for opt in opts:
            if opt.data_size() > 0:
                results.append((
                    int(opt.option()),
                    <bytes> (opt.data_ptr()[:opt.data_size()])
                ))
            else:
                results.append((
                    int(opt.option()),
                    b''
                ))
        return results

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppDHCP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppDHCP*> ptr
