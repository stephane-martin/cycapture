# -*- coding: utf-8 -*-

cdef extern from "wrap.h" namespace "Tins" nogil:
    cppclass dot11_pdu_option:
        dot11_pdu_option()
        dot11_pdu_option(uint8_t opt, size_t length, const uint8_t *data)
        uint8_t option() const
        void option(uint8_t opt)
        const uint8_t *data_ptr() const
        size_t data_size() const
        size_t length_field() const

cdef extern from "tins/dot11/dot11_base.h" namespace "Tins" nogil:
    PDUType dot11_pdu_flag "Tins::Dot11::pdu_flag"

    # typedef HWAddress<6> address_type; -> cppHWAddress6
    # typedef PDUOption<uint8_t, Dot11> option; -> dot11_pdu_option
    # typedef std::list<option> options_type;

    cppHWAddress6 dot11_BROADCAST "Tins::Dot11::BROADCAST"

    enum D11_OptionTypes "Tins::Dot11::OptionTypes":
        D11_SSID "Tins::Dot11::SSID",
        D11_SUPPORTED_RATES "Tins::Dot11::SUPPORTED_RATES",
        D11_FH_SET "Tins::Dot11::FH_SET",
        D11_DS_SET "Tins::Dot11::DS_SET",
        D11_CF_SET "Tins::Dot11::CF_SET",
        D11_TIM "Tins::Dot11::TIM",
        D11_IBSS_SET "Tins::Dot11::IBSS_SET",
        D11_COUNTRY "Tins::Dot11::COUNTRY",
        D11_HOPPING_PATTERN_PARAMS "Tins::Dot11::HOPPING_PATTERN_PARAMS",
        D11_HOPPING_PATTERN_TABLE "Tins::Dot11::HOPPING_PATTERN_TABLE",
        D11_REQUEST_INFORMATION "Tins::Dot11::REQUEST_INFORMATION",
        D11_BSS_LOAD "Tins::Dot11::BSS_LOAD",
        D11_EDCA "Tins::Dot11::EDCA",
        D11_TSPEC "Tins::Dot11::TSPEC",
        D11_TCLAS "Tins::Dot11::TCLAS",
        D11_SCHEDULE "Tins::Dot11::SCHEDULE",
        D11_CHALLENGE_TEXT "Tins::Dot11::CHALLENGE_TEXT",
        D11_POWER_CONSTRAINT "Tins::Dot11::POWER_CONSTRAINT",
        D11_POWER_CAPABILITY "Tins::Dot11::POWER_CAPABILITY",
        D11_TPC_REQUEST "Tins::Dot11::TPC_REQUEST",
        D11_TPC_REPORT "Tins::Dot11::TPC_REPORT",
        D11_SUPPORTED_CHANNELS "Tins::Dot11::SUPPORTED_CHANNELS",
        D11_CHANNEL_SWITCH "Tins::Dot11::CHANNEL_SWITCH",
        D11_MEASUREMENT_REQUEST "Tins::Dot11::MEASUREMENT_REQUEST",
        D11_MEASUREMENT_REPORT "Tins::Dot11::MEASUREMENT_REPORT",
        D11_QUIET "Tins::Dot11::QUIET",
        D11_IBSS_DFS "Tins::Dot11::IBSS_DFS",
        D11_ERP_INFORMATION "Tins::Dot11::ERP_INFORMATION",
        D11_TS_DELAY "Tins::Dot11::TS_DELAY",
        D11_TCLAS_PROCESSING "Tins::Dot11::TCLAS_PROCESSING",
        D11_QOS_CAPABILITY "Tins::Dot11::QOS_CAPABILITY",
        D11_RSN "Tins::Dot11::RSN",
        D11_EXT_SUPPORTED_RATES "Tins::Dot11::EXT_SUPPORTED_RATES",
        D11_VENDOR_SPECIFIC "Tins::Dot11::VENDOR_SPECIFIC"

    enum D11_ManagementSubtypes "Tins::Dot11::ManagementSubtypes":
        D11_ASSOC_REQ "Tins::Dot11::ASSOC_REQ",
        D11_ASSOC_RESP "Tins::Dot11::ASSOC_RESP",
        D11_REASSOC_REQ "Tins::Dot11::REASSOC_REQ",
        D11_REASSOC_RESP "Tins::Dot11::REASSOC_RESP",
        D11_PROBE_REQ "Tins::Dot11::PROBE_REQ",
        D11_PROBE_RESP "Tins::Dot11::PROBE_RESP",
        D11_BEACON "Tins::Dot11::BEACON",
        D11_ATIM "Tins::Dot11::ATIM",
        D11_DISASSOC "Tins::Dot11::DISASSOC",
        D11_AUTH "Tins::Dot11::AUTH",
        D11_DEAUTH "Tins::Dot11::DEAUTH"

    enum D11_ControlSubtypes "Tins::Dot11::ControlSubtypes":
        D11_BLOCK_ACK_REQ "Tins::Dot11::BLOCK_ACK_REQ",
        D11_BLOCK_ACK "Tins::Dot11::BLOCK_ACK",
        D11_PS "Tins::Dot11::PS",
        D11_RTS "Tins::Dot11::RTS",
        D11_CTS "Tins::Dot11::CTS",
        D11_ACK "Tins::Dot11::ACK",
        D11_CF_END "Tins::Dot11::CF_END",
        D11_CF_END_ACK "Tins::Dot11::CF_END_ACK"

    enum D11_DataSubtypes "Tins::Dot11::DataSubtypes":
        D11_DATA_DATA "Tins::Dot11::DATA_DATA",
        D11_DATA_CF_ACK "Tins::Dot11::DATA_CF_ACK",
        D11_DATA_CF_POLL "Tins::Dot11::DATA_CF_POLL",
        D11_DATA_CF_ACK_POLL "Tins::Dot11::DATA_CF_ACK_POLL",
        D11_DATA_NULL "Tins::Dot11::DATA_NULL",
        D11_CF_ACK "Tins::Dot11::CF_ACK",
        D11_CF_POLL "Tins::Dot11::CF_POLL",
        D11_CF_ACK_POLL "Tins::Dot11::CF_ACK_POLL",
        D11_QOS_DATA_DATA "Tins::Dot11::QOS_DATA_DATA",
        D11_QOS_DATA_CF_ACK "Tins::Dot11::QOS_DATA_CF_ACK",
        D11_QOS_DATA_CF_POLL "Tins::Dot11::QOS_DATA_CF_POLL",
        D11_QOS_DATA_CF_ACK_POLL "Tins::Dot11::QOS_DATA_CF_ACK_POLL",
        D11_QOS_DATA_NULL "Tins::Dot11::QOS_DATA_NULL"

    cppclass cppDot11 "Tins::Dot11" (cppPDU):
        cppDot11()
        cppDot11(const cppHWAddress6 &dst_hw_addr)
        cppDot11(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        small_uint2 protocol() const
        void protocol(small_uint2 new_proto)

        small_uint2 type() const
        void type(small_uint2 new_type)

        small_uint4 subtype() const
        void subtype(small_uint4 new_subtype)

        small_uint1 to_ds() const
        void to_ds(small_uint1 new_value)

        small_uint1 from_ds() const
        void from_ds(small_uint1 new_value)

        small_uint1 more_frag() const
        void more_frag(small_uint1 new_value)

        small_uint1 retry() const
        void retry(small_uint1 new_value)

        small_uint1 power_mgmt() const
        void power_mgmt(small_uint1 new_value)

        small_uint1 wep() const
        void wep(small_uint1 new_value)

        small_uint1 order() const
        void order(small_uint1 new_value)

        uint16_t duration_id() const
        void duration_id(uint16_t new_duration_id)

        cppHWAddress6 addr1() const
        void addr1(const cppHWAddress6 &new_addr1)

        void send(cppPacketSender &sender, const cppNetworkInterface &iface)

        void add_option(const dot11_pdu_option &opt)
        const dot11_pdu_option *search_option(D11_OptionTypes opt) const
        const cpp_list[dot11_pdu_option]& options() const

    # Note: allocate a cppDot11 with 'new' -> careful with memory management
    cppDot11* dot11_from_bytes "Tins::Dot11::from_bytes" (const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler


cdef class Dot11(PDU):
    cdef cppDot11* ptr

    @staticmethod
    cdef inline factory(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11()
        obj = Dot11(_raw=True)
        obj.ptr = new cppDot11(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

    cpdef send(self, PacketSender sender, NetworkInterface iface)

    @staticmethod
    cdef c_from_bytes(uint8_t* buf_addr, uint32_t size)


cdef extern from "tins/dot11/dot11_data.h" namespace "Tins" nogil:
    PDUType dot11_data_pdu_flag "Tins::Dot11Data::pdu_flag"
    PDUType dot11_qosdata_pdu_flag "Tins::Dot11QoSData::pdu_flag"

    cppclass cppDot11Data "Tins::Dot11Data" (cppDot11):
        cppDot11Data()
        cppDot11Data(const cppHWAddress6 &dst_hw_addr)
        cppDot11Data(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11Data(const uint8_t *buf, uint32_t total_sz) except +custom_exception_handler

        cppHWAddress6 addr2() const
        void addr2(const cppHWAddress6 &new_addr2)
        cppHWAddress6 addr3() const
        void addr3(const cppHWAddress6 &new_addr3)
        cppHWAddress6 addr4() const
        void addr4(const cppHWAddress6 &new_addr4)

        small_uint4 frag_num() const
        void frag_num(small_uint4 new_frag_num)

        small_uint12 seq_num() const
        void seq_num(small_uint12 new_seq_num)

        cppHWAddress6 src_addr() const
        cppHWAddress6 dst_addr() const
        cppHWAddress6 bssid_addr() const

    cppclass cppDot11QoSData "Tins::Dot11QoSData" (cppDot11Data):
        cppDot11QoSData()
        cppDot11QoSData(const cppHWAddress6 &dst_hw_addr)
        cppDot11QoSData(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11QoSData(const uint8_t *buf, uint32_t total_sz)

        uint16_t qos_control() const
        void qos_control(uint16_t new_qos_control)

cdef class Dot11Data(Dot11):

    @staticmethod
    cdef inline factory_dot11data(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11Data()
        obj = Dot11Data(_raw=True)
        obj.ptr = new cppDot11Data(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11Data*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj


cdef class Dot11QoSData(Dot11Data):

    @staticmethod
    cdef inline factory_dot11qosdata(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11QoSData()
        obj = Dot11QoSData(_raw=True)
        obj.ptr = new cppDot11QoSData(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11QoSData*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef extern from "tins/dot11/dot11_mgmt.h" namespace "Tins" nogil:
    # typedef std::vector<float> rates_type;
    # typedef std::vector<std::pair<uint8_t, uint8_t> > channels_type;
    # typedef std::vector<uint8_t> request_info_type;
    PDUType dot11_mgmt_pdu_flag "Tins::Dot11ManagementFrame::pdu_flag"

    enum D11MGMT_ReasonCodes "Tins::Dot11ManagementFrame::ReasonCodes":
        D11MGMT_UNSPECIFIED "Tins::Dot11ManagementFrame::UNSPECIFIED",
        D11MGMT_PREV_AUTH_NOT_VALID "Tins::Dot11ManagementFrame::PREV_AUTH_NOT_VALID",
        D11MGMT_STA_LEAVING_IBSS_ESS "Tins::Dot11ManagementFrame::STA_LEAVING_IBSS_ESS",
        D11MGMT_INACTIVITY "Tins::Dot11ManagementFrame::INACTIVITY",
        D11MGMT_CANT_HANDLE_STA "Tins::Dot11ManagementFrame::CANT_HANDLE_STA",
        D11MGMT_CLASS2_FROM_NO_AUTH "Tins::Dot11ManagementFrame::CLASS2_FROM_NO_AUTH",
        D11MGMT_CLASS3_FROM_NO_AUTH "Tins::Dot11ManagementFrame::CLASS3_FROM_NO_AUTH",
        D11MGMT_STA_LEAVING_BSS "Tins::Dot11ManagementFrame::STA_LEAVING_BSS",
        D11MGMT_STA_NOT_AUTH_WITH_STA "Tins::Dot11ManagementFrame::STA_NOT_AUTH_WITH_STA",
        D11MGMT_POW_CAP_NOT_VALID "Tins::Dot11ManagementFrame::POW_CAP_NOT_VALID",
        D11MGMT_SUPPORTED_CHANN_NOT_VALID "Tins::Dot11ManagementFrame::SUPPORTED_CHANN_NOT_VALID",
        D11MGMT_INVALID_CONTENT "Tins::Dot11ManagementFrame::INVALID_CONTENT",
        D11MGMT_MIC_FAIL "Tins::Dot11ManagementFrame::MIC_FAIL",
        D11MGMT_HANDSHAKE_TIMEOUT "Tins::Dot11ManagementFrame::HANDSHAKE_TIMEOUT",
        D11MGMT_GROUP_KEY_TIMEOUT "Tins::Dot11ManagementFrame::GROUP_KEY_TIMEOUT",
        D11MGMT_WRONG_HANDSHAKE "Tins::Dot11ManagementFrame::WRONG_HANDSHAKE",
        D11MGMT_INVALID_GROUP_CIPHER "Tins::Dot11ManagementFrame::INVALID_GROUP_CIPHER",
        D11MGMT_INVALID_PAIRWISE_CIPHER "Tins::Dot11ManagementFrame::INVALID_PAIRWISE_CIPHER",
        D11MGMT_INVALID_AKMP "Tins::Dot11ManagementFrame::INVALID_AKMP",
        D11MGMT_UNSOPPORTED_RSN_VERSION "Tins::Dot11ManagementFrame::UNSOPPORTED_RSN_VERSION",
        D11MGMT_INVALID_RSN_CAPABILITIES "Tins::Dot11ManagementFrame::INVALID_RSN_CAPABILITIES",
        D11MGMT_AUTH_FAILED "Tins::Dot11ManagementFrame::AUTH_FAILED",
        D11MGMT_CIPHER_SUITE_REJECTED "Tins::Dot11ManagementFrame::CIPHER_SUITE_REJECTED",
        D11MGMT_UNSPECIFIED_QOS_REASON "Tins::Dot11ManagementFrame::UNSPECIFIED_QOS_REASON",
        D11MGMT_NOT_ENOUGH_BANDWITH "Tins::Dot11ManagementFrame::NOT_ENOUGH_BANDWITH",
        D11MGMT_POOR_CHANNEL "Tins::Dot11ManagementFrame::POOR_CHANNEL",
        D11MGMT_STA_OUT_OF_LIMITS "Tins::Dot11ManagementFrame::STA_OUT_OF_LIMITS",
        D11MGMT_REQUESTED_BY_STA_LEAVING "Tins::Dot11ManagementFrame::REQUESTED_BY_STA_LEAVING",
        D11MGMT_REQUESTED_BY_STA_REJECT_MECHANISM "Tins::Dot11ManagementFrame::REQUESTED_BY_STA_REJECT_MECHANISM",
        D11MGMT_REQUESTED_BY_STA_REJECT_SETUP "Tins::Dot11ManagementFrame::REQUESTED_BY_STA_REJECT_SETUP",
        D11MGMT_REQUESTED_BY_STA_TIMEOUT "Tins::Dot11ManagementFrame::REQUESTED_BY_STA_TIMEOUT",
        D11MGMT_PEER_STA_NOT_SUPPORT_CIPHER "Tins::Dot11ManagementFrame::PEER_STA_NOT_SUPPORT_CIPHER"


    cppclass cppDot11ManagementFrame "Tins::Dot11ManagementFrame" (cppDot11):

        cppclass fh_params_set:
            uint16_t dwell_time
            uint8_t hop_set, hop_pattern, hop_index
            fh_params_set()
            fh_params_set(uint16_t dwell_time, uint8_t hop_set, uint8_t hop_pattern, uint8_t hop_index)

        cppclass cf_params_set:
            uint8_t cfp_count, cfp_period
            uint16_t cfp_max_duration, cfp_dur_remaining
            cf_params_set()
            cf_params_set(uint8_t cfp_count, uint8_t cfp_period, uint16_t cfp_max_duration, uint16_t cfp_dur_remaining)

        cppclass ibss_dfs_params:
            cppHWAddress6 dfs_owner
            uint8_t recovery_interval
            vector[pair[uint8_t, uint8_t]] channel_map
            ibss_dfs_params()
            ibss_dfs_params(const cppHWAddress6 &addr, uint8_t recovery_interval, const vector[pair[uint8_t, uint8_t]] &channels)

        cppclass country_params:
            string country
            vector[uint8_t] first_channel
            vector[uint8_t] number_channels
            vector[uint8_t] max_transmit_power
            country_params()
            country_params(const string &country, const vector[uint8_t] &first, const vector[uint8_t] &number, const vector[uint8_t] &m)

        cppclass fh_pattern_type:
            uint8_t flag, number_of_sets, modulus, offset
            vector[uint8_t] random_table
            fh_pattern_type()
            fh_pattern_type(uint8_t flag, uint8_t sets, uint8_t modulus, uint8_t offset, const vector[uint8_t]& table)

        cppclass channel_switch_type:
            uint8_t switch_mode, new_channel, switch_count
            channel_switch_type()
            channel_switch_type(uint8_t mode, uint8_t channel, uint8_t count)

        cppclass quiet_type:
            uint8_t quiet_count, quiet_period
            uint16_t quiet_duration, quiet_offset
            quiet_type()
            quiet_type(uint8_t count, uint8_t period, uint16_t duration, uint16_t offset)

        cppclass bss_load_type:
            uint16_t station_count
            uint16_t available_capacity
            uint8_t channel_utilization
            bss_load_type()
            bss_load_type(uint16_t count, uint8_t utilization, uint16_t capacity)

        cppclass tim_type:
            uint8_t dtim_count, dtim_period, bitmap_control
            vector[uint8_t] partial_virtual_bitmap
            tim_type()
            tim_type(uint8_t count, uint8_t period, uint8_t control, const vector[uint8_t] &bitmap)

        cppclass vendor_specific_type:
            cppHWAddress3 oui;
            vector[uint8_t] data;
            vendor_specific_type()
            vendor_specific_type(const cppHWAddress3 &oui)
            vendor_specific_type(const cppHWAddress3 &oui, const vector[uint8_t] &data)

        cppHWAddress6 addr2() const
        void addr2(const cppHWAddress6 &new_addr2)

        cppHWAddress6 addr3() const
        void addr3(const cppHWAddress6 &new_addr3)

        const cppHWAddress6 &addr4() const
        void addr4(const cppHWAddress6 &new_addr4)

        small_uint4 frag_num() const
        void frag_num(small_uint4 new_frag_num)

        small_uint12 seq_num() const
        void seq_num(small_uint12 new_seq_num)

        # option set helpers
        void ssid(const string &new_ssid)
        void rsn_information(const cppRSNInformation& info)
        void supported_rates(const vector[float] &new_rates)
        void extended_supported_rates(const vector[float] &new_rates)
        void qos_capability(uint8_t new_qos_capability)
        void power_capability(uint8_t min_power, uint8_t max_power)
        void supported_channels(const vector[pair[uint8_t, uint8_t]] &new_channels)
        void edca_parameter_set(uint32_t ac_be, uint32_t ac_bk, uint32_t ac_vi, uint32_t ac_vo)
        void request_information(const vector[uint8_t] elements)
        void fh_parameter_set(const cppDot11ManagementFrame.fh_params_set &fh_params)
        void ds_parameter_set(uint8_t current_channel)
        void cf_parameter_set(const cppDot11ManagementFrame.cf_params_set &params)
        void ibss_parameter_set(uint16_t atim_window)
        void ibss_dfs(const cppDot11ManagementFrame.ibss_dfs_params &params)
        void country(const cppDot11ManagementFrame.country_params &params)
        void fh_parameters(uint8_t prime_radix, uint8_t number_channels)
        void fh_pattern_table(const cppDot11ManagementFrame.fh_pattern_type &params)
        void power_constraint(uint8_t local_power_constraint)
        void channel_switch(const cppDot11ManagementFrame.channel_switch_type &data)
        void quiet(const cppDot11ManagementFrame.quiet_type &data)
        void tpc_report(uint8_t transmit_power, uint8_t link_margin)
        void erp_information(uint8_t value)
        void bss_load(const cppDot11ManagementFrame.bss_load_type &data)
        void tim(const cppDot11ManagementFrame.tim_type &data)
        void challenge_text(const string &text)
        void vendor_specific(const cppDot11ManagementFrame.vendor_specific_type &data)

        # option search helpers

        cppRSNInformation rsn_information() except +custom_exception_handler
        string ssid() except +custom_exception_handler
        vector[float] supported_rates() except +custom_exception_handler
        vector[float] extended_supported_rates() except +custom_exception_handler
        uint8_t qos_capability() except +custom_exception_handler
        pair[uint8_t, uint8_t] power_capability() except +custom_exception_handler
        vector[pair[uint8_t, uint8_t]] supported_channels() except +custom_exception_handler
        vector[uint8_t] request_information() except +custom_exception_handler
        cppDot11ManagementFrame.fh_params_set fh_parameter_set() except +custom_exception_handler
        uint8_t ds_parameter_set() except +custom_exception_handler
        cppDot11ManagementFrame.cf_params_set cf_parameter_set() except +custom_exception_handler
        uint16_t ibss_parameter_set() except +custom_exception_handler
        cppDot11ManagementFrame.ibss_dfs_params ibss_dfs() except +custom_exception_handler
        cppDot11ManagementFrame.country_params country() except +custom_exception_handler
        pair[uint8_t, uint8_t] fh_parameters() except +custom_exception_handler
        cppDot11ManagementFrame.fh_pattern_type fh_pattern_table() except +custom_exception_handler
        uint8_t power_constraint() except +custom_exception_handler
        cppDot11ManagementFrame.channel_switch_type channel_switch() except +custom_exception_handler
        cppDot11ManagementFrame.quiet_type quiet() except +custom_exception_handler
        pair[uint8_t, uint8_t] tpc_report() except +custom_exception_handler
        uint8_t erp_information() except +custom_exception_handler
        cppDot11ManagementFrame.bss_load_type bss_load() except +custom_exception_handler
        cppDot11ManagementFrame.tim_type tim() except +custom_exception_handler
        string challenge_text() except +custom_exception_handler
        cppDot11ManagementFrame.vendor_specific_type vendor_specific() except +custom_exception_handler

        cppclass capability_information:
            capability_information()

            cpp_bool ess() const
            void ess(cpp_bool new_value)

            cpp_bool ibss() const
            void ibss(cpp_bool new_value)

            cpp_bool cf_poll() const
            void cf_poll(cpp_bool new_value)

            cpp_bool cf_poll_req() const
            void cf_poll_req(cpp_bool new_value)

            cpp_bool privacy() const
            void privacy(cpp_bool new_value)

            cpp_bool short_preamble() const
            void short_preamble(cpp_bool new_value)

            cpp_bool pbcc() const
            void pbcc(cpp_bool new_value)

            cpp_bool channel_agility() const
            void channel_agility(cpp_bool new_value)

            cpp_bool spectrum_mgmt() const
            void spectrum_mgmt(cpp_bool new_value)

            cpp_bool qos() const
            void qos(cpp_bool new_value)

            cpp_bool sst() const
            void sst(cpp_bool new_value)

            cpp_bool apsd() const
            void apsd(cpp_bool new_value)

            cpp_bool reserved() const
            void reserved(cpp_bool new_value)

            cpp_bool dsss_ofdm() const
            void dsss_ofdm(cpp_bool new_value)

            cpp_bool delayed_block_ack() const
            void delayed_block_ack(cpp_bool new_value)

            cpp_bool immediate_block_ack() const
            void immediate_block_ack(cpp_bool new_value)

    cppDot11ManagementFrame.fh_params_set fh_params_set_from_option "Tins::Dot11ManagementFrame::fh_params_set::from_option" (const dot11_pdu_option& option)
    cppDot11ManagementFrame.cf_params_set cf_params_set_from_option "Tins::Dot11ManagementFrame::cf_params_set::from_option" (const dot11_pdu_option &opt)
    cppDot11ManagementFrame.ibss_dfs_params ibss_dfs_params_from_option "Tins::Dot11ManagementFrame::ibss_dfs_params::from_option" (const dot11_pdu_option &opt)
    cppDot11ManagementFrame.country_params country_params_from_option "Tins::Dot11ManagementFrame::country_params::from_option" (const dot11_pdu_option &opt)
    cppDot11ManagementFrame.fh_pattern_type fh_pattern_type_from_option "Tins::Dot11ManagementFrame::fh_pattern_type::from_option" (const dot11_pdu_option &opt)
    cppDot11ManagementFrame.channel_switch_type channel_switch_type_from_option "Tins::Dot11ManagementFrame::channel_switch_type::from_option" (const dot11_pdu_option &opt)
    cppDot11ManagementFrame.quiet_type quiet_type_from_option "Tins::Dot11ManagementFrame::quiet_type::from_option" (const dot11_pdu_option &opt)
    cppDot11ManagementFrame.bss_load_type bss_load_type_from_option "Tins::Dot11ManagementFrame::bss_load_type::from_option" (const dot11_pdu_option &opt)
    cppDot11ManagementFrame.tim_type tim_type_from_option "Tins::Dot11ManagementFrame::tim_type::from_option" (const dot11_pdu_option &opt)
    cppDot11ManagementFrame.vendor_specific_type vendor_specific_type_from_option "Tins::Dot11ManagementFrame::vendor_specific_type::from_option" (const dot11_pdu_option &opt)


cdef class Capabilities(object):
    cdef cppDot11ManagementFrame.capability_information cap_info

    @staticmethod
    cdef inline factory(cppDot11ManagementFrame.capability_information& info):
        obj = Capabilities()
        obj.cap_info = info
        return obj


cdef class Dot11ManagementFrame(Dot11):
    pass


cdef extern from "tins/dot11/dot11_assoc.h" namespace "Tins" nogil:
    PDUType dot11_diassoc_pdu_flag "Tins::Dot11Disassoc::pdu_flag"
    PDUType dot11_assocrequest_pdu_flag "Tins::Dot11AssocRequest::pdu_flag"
    PDUType dot11_assocresponse_pdu_flag "Tins::Dot11AssocResponse::pdu_flag"
    PDUType dot11_reassocrequest_pdu_flag "Tins::Dot11ReAssocRequest::pdu_flag"
    PDUType dot11_reassocresponse_pdu_flag "Tins::Dot11ReAssocResponse::pdu_flag"

    cppclass cppDot11Disassoc "Tins::Dot11Disassoc" (cppDot11ManagementFrame):
        cppDot11Disassoc()
        cppDot11Disassoc(const cppHWAddress6 &dst_hw_addr)
        cppDot11Disassoc(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11Disassoc(const uint8_t *buf, uint32_t total_sz)
        uint16_t reason_code() const
        void reason_code(uint16_t new_reason_code)

    cppclass cppDot11AssocRequest "Tins::Dot11AssocRequest" (cppDot11ManagementFrame):
        cppDot11AssocRequest()
        cppDot11AssocRequest(const cppHWAddress6 &dst_hw_addr)
        cppDot11AssocRequest(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11AssocRequest(const uint8_t *buf, uint32_t total_sz)
        # const cppDot11ManagementFrame.capability_information& capabilities() const
        cppDot11ManagementFrame.capability_information& capabilities()
        uint16_t listen_interval() const
        void listen_interval(uint16_t new_listen_interval)

    cppclass cppDot11AssocResponse "Tins::Dot11AssocResponse" (cppDot11ManagementFrame):
        cppDot11AssocResponse()
        cppDot11AssocResponse(const cppHWAddress6 &dst_hw_addr)
        cppDot11AssocResponse(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11AssocResponse(const uint8_t *buf, uint32_t total_sz)
        # const cppDot11ManagementFrame.capability_information& capabilities() const
        cppDot11ManagementFrame.capability_information& capabilities()
        uint16_t status_code() const
        void status_code(uint16_t new_status_code)
        uint16_t aid() const
        void aid(uint16_t new_aid)

    cppclass cppDot11ReAssocRequest "Tins::Dot11ReAssocRequest" (cppDot11ManagementFrame):
        cppDot11ReAssocRequest()
        cppDot11ReAssocRequest(const cppHWAddress6 &dst_hw_addr)
        cppDot11ReAssocRequest(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11ReAssocRequest(const uint8_t *buf, uint32_t total_sz)
        # const cppDot11ManagementFrame.capability_information& capabilities() const
        cppDot11ManagementFrame.capability_information& capabilities()
        uint16_t listen_interval() const
        void listen_interval(uint16_t new_listen_interval)
        cppHWAddress6 current_ap() const
        void current_ap(const cppHWAddress6 &new_current_ap)

    cppclass cppDot11ReAssocResponse "Tins::Dot11ReAssocResponse" (cppDot11ManagementFrame):
        cppDot11ReAssocResponse()
        cppDot11ReAssocResponse(const cppHWAddress6 &dst_hw_addr)
        cppDot11ReAssocResponse(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11ReAssocResponse(const uint8_t *buf, uint32_t total_sz)
        # const cppDot11ManagementFrame.capability_information& capabilities() const
        cppDot11ManagementFrame.capability_information& capabilities()
        uint16_t status_code() const
        void status_code(uint16_t new_status_code)
        uint16_t aid() const
        void aid(uint16_t new_aid)


cdef class Dot11Disassoc(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11disassoc(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11Disassoc()
        obj = Dot11Disassoc(_raw=True)
        obj.ptr = new cppDot11Disassoc(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11Disassoc*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11AssocRequest(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11assocrequest(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11AssocRequest()
        obj = Dot11AssocRequest(_raw=True)
        obj.ptr = new cppDot11AssocRequest(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11AssocRequest*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11AssocResponse(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11assocresponse(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11AssocResponse()
        obj = Dot11AssocResponse(_raw=True)
        obj.ptr = new cppDot11AssocResponse(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11AssocResponse*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11ReAssocRequest(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11reassocrequest(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11ReAssocRequest()
        obj = Dot11ReAssocRequest(_raw=True)
        obj.ptr = new cppDot11ReAssocRequest(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11ReAssocRequest*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11ReAssocResponse(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11reassocresponse(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11ReAssocResponse()
        obj = Dot11ReAssocResponse(_raw=True)
        obj.ptr = new cppDot11ReAssocResponse(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11ReAssocResponse*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj


cdef extern from "tins/dot11/dot11_auth.h" namespace "Tins" nogil:
    PDUType dot11_auth_pdu_flag "Tins::Dot11Authentication::pdu_flag"
    PDUType dot11_deauth_pdu_flag "Tins::Dot11Deauthentication::pdu_flag"

    cppclass cppDot11Authentication "Tins::Dot11Authentication" (cppDot11ManagementFrame):
        cppDot11Authentication()
        cppDot11Authentication(const cppHWAddress6 &dst_hw_addr)
        cppDot11Authentication(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11Authentication(const uint8_t *buf, uint32_t total_sz)
        uint16_t auth_algorithm() const
        void auth_algorithm(uint16_t new_auth_algorithm)
        uint16_t auth_seq_number() const
        void auth_seq_number(uint16_t new_auth_seq_number)
        uint16_t status_code() const
        void status_code(uint16_t new_status_code)

    cppclass cppDot11Deauthentication "Tins::Dot11Deauthentication" (cppDot11ManagementFrame):
        cppDot11Deauthentication()
        cppDot11Deauthentication(const cppHWAddress6 &dst_hw_addr)
        cppDot11Deauthentication(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11Deauthentication(const uint8_t *buf, uint32_t total_sz)
        uint16_t reason_code() const
        void reason_code(uint16_t new_reason_code)

cdef class Dot11Authentication(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11auth(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11Authentication()
        obj = Dot11Authentication(_raw=True)
        obj.ptr = new cppDot11Authentication(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11Authentication*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11Deauthentication(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11deauth(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11Deauthentication()
        obj = Dot11Deauthentication(_raw=True)
        obj.ptr = new cppDot11Deauthentication(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11Deauthentication*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj


cdef extern from "tins/dot11/dot11_beacon.h" namespace "Tins" nogil:
    PDUType dot11_beacon_pdu_flag "Tins::Dot11Beacon::pdu_flag"

    cppclass cppDot11Beacon "Tins::Dot11Beacon" (cppDot11ManagementFrame):
        cppDot11Beacon()
        cppDot11Beacon(const cppHWAddress6 &dst_hw_addr)
        cppDot11Beacon(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11Beacon(const uint8_t *buf, uint32_t total_sz)

        uint64_t timestamp() const
        void timestamp(uint64_t new_timestamp)
        uint16_t interval() const
        void interval(uint16_t new_interval)
        cppDot11ManagementFrame.capability_information& capabilities()

cdef class Dot11Beacon(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11beacon(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11Beacon()
        obj = Dot11Beacon(_raw=True)
        obj.ptr = new cppDot11Beacon(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11Beacon*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef extern from "tins/dot11/dot11_probe.h" namespace "Tins" nogil:
    PDUType dot11_probe_request_pdu_flag "Tins::Dot11ProbeRequest::pdu_flag"
    PDUType dot11_probe_response_pdu_flag "Tins::Dot11ProbeResponse::pdu_flag"

    cppclass cppDot11ProbeRequest "Tins::Dot11ProbeRequest" (cppDot11ManagementFrame):
        cppDot11ProbeRequest()
        cppDot11ProbeRequest(const cppHWAddress6 &dst_hw_addr)
        cppDot11ProbeRequest(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11ProbeRequest(const uint8_t *buf, uint32_t total_sz)

    cppclass cppDot11ProbeResponse "Tins::Dot11ProbeResponse" (cppDot11ManagementFrame):
        cppDot11ProbeResponse()
        cppDot11ProbeResponse(const cppHWAddress6 &dst_hw_addr)
        cppDot11ProbeResponse(const cppHWAddress6 &dst_hw_addr, const cppHWAddress6 &src_hw_addr)
        cppDot11ProbeResponse(const uint8_t *buf, uint32_t total_sz)

        uint64_t timestamp() const
        void timestamp(uint64_t new_timestamp)
        uint16_t interval() const
        void interval(uint16_t new_interval)
        cppDot11ManagementFrame.capability_information& capabilities()


cdef class Dot11ProbeRequest(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11proberequest(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11ProbeRequest()
        obj = Dot11ProbeRequest(_raw=True)
        obj.ptr = new cppDot11ProbeRequest(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11ProbeRequest*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11ProbeResponse(Dot11ManagementFrame):

    @staticmethod
    cdef inline factory_dot11proberesponse(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11ProbeResponse()
        obj = Dot11ProbeResponse(_raw=True)
        obj.ptr = new cppDot11ProbeResponse(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11ProbeResponse*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef extern from "tins/dot11/dot11_control.h" namespace "Tins" nogil:
    PDUType dot11_probe_request_pdu_flag "Tins::Dot11Control::pdu_flag"
    PDUType dot11_controlta_pdu_flag "Tins::Dot11ControlTA::pdu_flag"
    PDUType dot11_rts_pdu_flag "Tins::Dot11RTS::pdu_flag"
    PDUType dot11_pspoll_pdu_flag "Tins::Dot11PSPoll::pdu_flag"
    PDUType dot11_cfend_pdu_flag "Tins::Dot11CFEnd::pdu_flag"
    PDUType dot11_endcfack_pdu_flag "Tins::Dot11EndCFAck::pdu_flag"
    PDUType dot11_ack_pdu_flag "Tins::Dot11Ack::pdu_flag"
    PDUType dot11_blockackrequest_pdu_flag "Tins::Dot11BlockAckRequest::pdu_flag"
    PDUType dot11_blockack_pdu_flag "Tins::Dot11BlockAck::pdu_flag"

    cppclass cppDot11Control "Tins::Dot11Control" (cppDot11):
        cppDot11Control()
        cppDot11Control(const cppHWAddress6 &dst_addr)
        cppDot11Control(const uint8_t *buf, uint32_t total_sz)

    cppclass cppDot11ControlTA "Tins::Dot11ControlTA" (cppDot11Control):
        cppHWAddress6 target_addr() const
        void target_addr(const cppHWAddress6 &addr)

    cppclass cppDot11RTS "Tins::Dot11RTS" (cppDot11ControlTA):
        cppDot11RTS()
        cppDot11RTS(const cppHWAddress6 &dst_addr)
        cppDot11RTS(const cppHWAddress6 &dst_addr, const cppHWAddress6 &target_addr)
        cppDot11RTS(const uint8_t *buf, uint32_t total_sz)

    cppclass cppDot11PSPoll "Tins::Dot11PSPoll" (cppDot11ControlTA):
        cppDot11PSPoll()
        cppDot11PSPoll(const cppHWAddress6 &dst_addr)
        cppDot11PSPoll(const cppHWAddress6 &dst_addr, const cppHWAddress6 &target_addr)
        cppDot11PSPoll(const uint8_t *buf, uint32_t total_sz)

    cppclass cppDot11CFEnd "Tins::Dot11CFEnd" (cppDot11ControlTA):
        cppDot11CFEnd()
        cppDot11CFEnd(const cppHWAddress6 &dst_addr)
        cppDot11CFEnd(const cppHWAddress6 &dst_addr, const cppHWAddress6 &target_addr)
        cppDot11CFEnd(const uint8_t *buf, uint32_t total_sz)

    cppclass cppDot11EndCFAck "Tins::Dot11EndCFAck" (cppDot11ControlTA):
        cppDot11EndCFAck()
        cppDot11EndCFAck(const cppHWAddress6 &dst_addr)
        cppDot11EndCFAck(const cppHWAddress6 &dst_addr, const cppHWAddress6 &target_addr)
        cppDot11EndCFAck(const uint8_t *buf, uint32_t total_sz)

    cppclass cppDot11Ack "Tins::Dot11Ack" (cppDot11Control):
        cppDot11Ack()
        cppDot11Ack(const cppHWAddress6 &dst_addr)
        cppDot11Ack(const uint8_t *buf, uint32_t total_sz)

    cppclass cppDot11BlockAckRequest "Tins::Dot11BlockAckRequest" (cppDot11ControlTA):
        cppDot11BlockAckRequest()
        cppDot11BlockAckRequest(const cppHWAddress6 &dst_addr)
        cppDot11BlockAckRequest(const cppHWAddress6 &dst_addr, const cppHWAddress6 &target_addr)
        cppDot11BlockAckRequest(const uint8_t *buf, uint32_t total_sz)

        small_uint4 bar_control() const
        void bar_control(small_uint4 bar)
        small_uint12 start_sequence() const
        void start_sequence(small_uint12 seq)
        small_uint4 fragment_number() const
        void fragment_number(small_uint4 frag)

    cppclass cppDot11BlockAck "Tins::Dot11BlockAck" (cppDot11ControlTA):
        cppDot11BlockAck()
        cppDot11BlockAck(const cppHWAddress6 &dst_addr)
        cppDot11BlockAck(const cppHWAddress6 &dst_addr, const cppHWAddress6 &target_addr)
        cppDot11BlockAck(const uint8_t *buf, uint32_t total_sz)

        small_uint4 bar_control() const
        void bar_control(small_uint4 bar)
        small_uint12 start_sequence() const
        void start_sequence(small_uint12 seq)
        small_uint4 fragment_number() const
        void fragment_number(small_uint4 frag)

        const uint8_t *bitmap() const       # The returned pointer <b>must not</b> be free'd.
        void bitmap(const uint8_t *bit)

    size_t dot11_block_ack_bitmap_size "Tins::Dot11BlockAck::bitmap_size"

cdef class Dot11Control(Dot11):

    @staticmethod
    cdef inline factory_dot11control(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11Control()
        obj = Dot11Control(_raw=True)
        obj.ptr = new cppDot11Control(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11Control*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11RTS(Dot11Control):

    @staticmethod
    cdef inline factory_dot11rts(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11RTS()
        obj = Dot11RTS(_raw=True)
        obj.ptr = new cppDot11RTS(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11RTS*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11PSPoll(Dot11Control):

    @staticmethod
    cdef inline factory_dot11pspoll(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11PSPoll()
        obj = Dot11PSPoll(_raw=True)
        obj.ptr = new cppDot11PSPoll(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11PSPoll*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11CFEnd(Dot11Control):

    @staticmethod
    cdef inline factory_dot11cfend(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11CFEnd()
        obj = Dot11CFEnd(_raw=True)
        obj.ptr = new cppDot11CFEnd(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11CFEnd*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11EndCFAck(Dot11Control):

    @staticmethod
    cdef inline factory_dot11endcfack(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11EndCFAck()
        obj = Dot11EndCFAck(_raw=True)
        obj.ptr = new cppDot11EndCFAck(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11EndCFAck*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11Ack(Dot11Control):

    @staticmethod
    cdef inline factory_dot11ack(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11Ack()
        obj = Dot11Ack(_raw=True)
        obj.ptr = new cppDot11Ack(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11Ack*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11BlockAckRequest(Dot11Control):

    @staticmethod
    cdef inline factory_dot11blockackrequest(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11BlockAckRequest()
        obj = Dot11BlockAckRequest(_raw=True)
        obj.ptr = new cppDot11BlockAckRequest(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11BlockAckRequest*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj

cdef class Dot11BlockAck(Dot11Control):

    @staticmethod
    cdef inline factory_dot11blockack(cppPDU* ptr, uint8_t* buf, int size, object parent):
        if ptr is NULL and buf is NULL:
            return Dot11BlockAck()
        obj = Dot11BlockAck(_raw=True)
        obj.ptr = new cppDot11BlockAck(<uint8_t*> buf, <uint32_t> size) if ptr is NULL else <cppDot11BlockAck*> ptr
        obj.base_ptr = <cppPDU*> obj.ptr
        obj.parent = parent
        return obj


