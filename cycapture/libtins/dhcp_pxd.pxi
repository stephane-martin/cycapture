# -*- coding: utf-8 -*-

cdef extern from "wrap.h" namespace "Tins" nogil:
    cdef cppclass dhcp_option:
        dhcp_option()
        dhcp_option(uint8_t opt)
        dhcp_option(uint8_t opt, size_t length, const uint8_t *data)
        dhcp_option(const dhcp_option& rhs)
        dhcp_option& operator=(const dhcp_option& rhs)
        uint8_t option() const
        const uint8_t *data_ptr() const
        size_t data_size() const
        size_t length_field() const
        #T to()[T] const

cdef extern from "tins/tcp.h" namespace "Tins" nogil:
    PDUType dhcp_pdu_flag "Tins::DHCP::pdu_flag"

    enum DHCP_Flags     "Tins::DHCP::Flags":
        DHCP_DISCOVER   "Tins::DHCP::DISCOVER",
        DHCP_OFFER      "Tins::DHCP::OFFER",
        DHCP_REQUEST	"Tins::DHCP::REQUEST",
        DHCP_DECLINE    "Tins::DHCP::DECLINE",
        DHCP_ACK        "Tins::DHCP::ACK",
        DHCP_NAK        "Tins::DHCP::NAK",
        DHCP_RELEASE	"Tins::DHCP::RELEASE",
        DHCP_INFORM     "Tins::DHCP::INFORM"

    enum DHCP_OptionTypes "Tins::DHCP::OptionTypes":
        DHCP_PAD "Tins::DHCP::PAD",
        DHCP_SUBNET_MASK "Tins::DHCP::SUBNET_MASK",
        DHCP_TIME_OFFSET "Tins::DHCP::TIME_OFFSET",
        DHCP_ROUTERS "Tins::DHCP::ROUTERS",
        DHCP_TIME_SERVERS "Tins::DHCP::TIME_SERVERS",
        DHCP_NAME_SERVERS "Tins::DHCP::NAME_SERVERS",
        DHCP_DOMAIN_NAME_SERVERS "Tins::DHCP::DOMAIN_NAME_SERVERS",
        DHCP_LOG_SERVERS "Tins::DHCP::LOG_SERVERS",
        DHCP_COOKIE_SERVERS "Tins::DHCP::COOKIE_SERVERS",
        DHCP_LPR_SERVERS "Tins::DHCP::LPR_SERVERS",
        DHCP_IMPRESS_SERVERS "Tins::DHCP::IMPRESS_SERVERS",
        DHCP_RESOURCE_LOCATION_SERVERS "Tins::DHCP::RESOURCE_LOCATION_SERVERS",
        DHCP_HOST_NAME "Tins::DHCP::HOST_NAME",
        DHCP_BOOT_SIZE "Tins::DHCP::BOOT_SIZE",
        DHCP_MERIT_DUMP "Tins::DHCP::MERIT_DUMP",
        DHCP_DOMAIN_NAME "Tins::DHCP::DOMAIN_NAME",
        DHCP_SWAP_SERVER "Tins::DHCP::SWAP_SERVER",
        DHCP_ROOT_PATH "Tins::DHCP::ROOT_PATH",
        DHCP_EXTENSIONS_PATH "Tins::DHCP::EXTENSIONS_PATH",
        DHCP_IP_FORWARDING "Tins::DHCP::IP_FORWARDING",
        DHCP_NON_LOCAL_SOURCE_ROUTING "Tins::DHCP::NON_LOCAL_SOURCE_ROUTING",
        DHCP_POLICY_FILTER "Tins::DHCP::POLICY_FILTER",
        DHCP_MAX_DGRAM_REASSEMBLY "Tins::DHCP::MAX_DGRAM_REASSEMBLY",
        DHCP_DEFAULT_IP_TTL "Tins::DHCP::DEFAULT_IP_TTL",
        DHCP_PATH_MTU_AGING_TIMEOUT "Tins::DHCP::PATH_MTU_AGING_TIMEOUT",
        DHCP_PATH_MTU_PLATEAU_TABLE "Tins::DHCP::PATH_MTU_PLATEAU_TABLE",
        DHCP_INTERFACE_MTU "Tins::DHCP::INTERFACE_MTU",
        DHCP_ALL_SUBNETS_LOCAL "Tins::DHCP::ALL_SUBNETS_LOCAL",
        DHCP_BROADCAST_ADDRESS "Tins::DHCP::BROADCAST_ADDRESS",
        DHCP_PERFORM_MASK_DISCOVERY "Tins::DHCP::PERFORM_MASK_DISCOVERY",
        DHCP_MASK_SUPPLIER "Tins::DHCP::MASK_SUPPLIER",
        DHCP_ROUTER_DISCOVERY "Tins::DHCP::ROUTER_DISCOVERY",
        DHCP_ROUTER_SOLICITATION_ADDRESS "Tins::DHCP::ROUTER_SOLICITATION_ADDRESS",
        DHCP_STATIC_ROUTES "Tins::DHCP::STATIC_ROUTES",
        DHCP_TRAILER_ENCAPSULATION "Tins::DHCP::TRAILER_ENCAPSULATION",
        DHCP_ARP_CACHE_TIMEOUT "Tins::DHCP::ARP_CACHE_TIMEOUT",
        DHCP_IEEE802_3_ENCAPSULATION "Tins::DHCP::IEEE802_3_ENCAPSULATION",
        DHCP_DEFAULT_TCP_TTL "Tins::DHCP::DEFAULT_TCP_TTL",
        DHCP_TCP_KEEPALIVE_INTERVAL "Tins::DHCP::TCP_KEEPALIVE_INTERVAL",
        DHCP_TCP_KEEPALIVE_GARBAGE "Tins::DHCP::TCP_KEEPALIVE_GARBAGE",
        DHCP_NIS_DOMAIN "Tins::DHCP::NIS_DOMAIN",
        DHCP_NIS_SERVERS "Tins::DHCP::NIS_SERVERS",
        DHCP_NTP_SERVERS "Tins::DHCP::NTP_SERVERS",
        DHCP_VENDOR_ENCAPSULATED_OPTIONS "Tins::DHCP::VENDOR_ENCAPSULATED_OPTIONS",
        DHCP_NETBIOS_NAME_SERVERS "Tins::DHCP::NETBIOS_NAME_SERVERS",
        DHCP_NETBIOS_DD_SERVER "Tins::DHCP::NETBIOS_DD_SERVER",
        DHCP_NETBIOS_NODE_TYPE "Tins::DHCP::NETBIOS_NODE_TYPE",
        DHCP_NETBIOS_SCOPE "Tins::DHCP::NETBIOS_SCOPE",
        DHCP_FONT_SERVERS "Tins::DHCP::FONT_SERVERS",
        DHCP_X_DISPLAY_MANAGER "Tins::DHCP::X_DISPLAY_MANAGER",
        DHCP_DHCP_REQUESTED_ADDRESS "Tins::DHCP::DHCP_REQUESTED_ADDRESS",
        DHCP_DHCP_LEASE_TIME "Tins::DHCP::DHCP_LEASE_TIME",
        DHCP_DHCP_OPTION_OVERLOAD "Tins::DHCP::DHCP_OPTION_OVERLOAD",
        DHCP_DHCP_MESSAGE_TYPE "Tins::DHCP::DHCP_MESSAGE_TYPE",
        DHCP_DHCP_SERVER_IDENTIFIER "Tins::DHCP::DHCP_SERVER_IDENTIFIER",
        DHCP_DHCP_PARAMETER_REQUEST_LIST "Tins::DHCP::DHCP_PARAMETER_REQUEST_LIST",
        DHCP_DHCP_MESSAGE "Tins::DHCP::DHCP_MESSAGE",
        DHCP_DHCP_MAX_MESSAGE_SIZE "Tins::DHCP::DHCP_MAX_MESSAGE_SIZE",
        DHCP_DHCP_RENEWAL_TIME "Tins::DHCP::DHCP_RENEWAL_TIME",
        DHCP_DHCP_REBINDING_TIME "Tins::DHCP::DHCP_REBINDING_TIME",
        DHCP_VENDOR_CLASS_IDENTIFIER "Tins::DHCP::VENDOR_CLASS_IDENTIFIER",
        DHCP_DHCP_CLIENT_IDENTIFIER "Tins::DHCP::DHCP_CLIENT_IDENTIFIER",
        DHCP_NWIP_DOMAIN_NAME "Tins::DHCP::NWIP_DOMAIN_NAME",
        DHCP_NWIP_SUBOPTIONS "Tins::DHCP::NWIP_SUBOPTIONS",
        DHCP_USER_CLASS "Tins::DHCP::USER_CLASS",
        DHCP_FQDN "Tins::DHCP::FQDN",
        DHCP_DHCP_AGENT_OPTIONS "Tins::DHCP::DHCP_AGENT_OPTIONS",
        DHCP_SUBNET_SELECTION "Tins::DHCP::SUBNET_SELECTION",
        DHCP_AUTHENTICATE "Tins::DHCP::AUTHENTICATE",
        DHCP_END "Tins::DHCP::END"

    cdef cppclass cppDHCP "Tins::DHCP" (cppBootP):
        cppDHCP()
        cppDHCP(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        void add_option(const dhcp_option &opt)
        const dhcp_option* search_option(DHCP_OptionTypes opt) const
        const cpp_list[dhcp_option] options() const

        uint8_t type() except +custom_exception_handler
        void type(DHCP_Flags t)

        void end()

        cppIPv4Address server_identifier() except +custom_exception_handler
        void server_identifier(cppIPv4Address ip)

        uint32_t lease_time() except +custom_exception_handler
        void lease_time(uint32_t time)

        uint32_t renewal_time() except +custom_exception_handler
        void renewal_time(uint32_t time)

        uint32_t rebind_time() except +custom_exception_handler
        void rebind_time(uint32_t time)

        cppIPv4Address subnet_mask() except +custom_exception_handler
        void subnet_mask(cppIPv4Address mask)

        vector[cppIPv4Address] routers() except +custom_exception_handler
        void routers(const vector[cppIPv4Address] &routers)

        vector[cppIPv4Address] domain_name_servers() except +custom_exception_handler
        void domain_name_servers(const vector[cppIPv4Address] &dns)

        cppIPv4Address broadcast() except +custom_exception_handler
        void broadcast(cppIPv4Address addr)

        cppIPv4Address requested_ip() except +custom_exception_handler
        void requested_ip(cppIPv4Address addr)

        string domain_name() except +custom_exception_handler
        void domain_name(const string &name)

        string hostname() except +custom_exception_handler
        void hostname(const string &name)


cdef class DHCP(BootP):
    cpdef end(self)
    cpdef add_option(self, identifier, data=?)
    cpdef search_option(self, identifier)
    cpdef options(self)
