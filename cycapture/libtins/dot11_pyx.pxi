# -*- coding: utf-8 -*-

"""
Base Dot11 packet python class
"""

fh_params = namedtuple('fh_params', ['dwell_time', 'hop_set', 'hop_pattern', 'hop_index'])
cf_params = namedtuple('cf_params', ['cfp_count', 'cfp_period', 'cfp_max_duration', 'cfp_dur_remaining'])
dfs_params = namedtuple('dfs_params', ['dfs_owner', 'recovery_interval', 'channel_map'])
country_params = namedtuple('country_params', ['country', 'first_channel', 'number_channels', 'max_transmit_power'])
fh_pattern = namedtuple('fh_pattern', ['flag', 'number_of_sets', 'modulus', 'offset', 'random_table'])
channel_switch_t = namedtuple('channel_switch_t', ['switch_mode', 'new_channel', 'count'])
quiet_t = namedtuple('quiet_t', ['quiet_count', 'quiet_period', 'quiet_duration', 'quiet_offset'])
bss_load_t = namedtuple('bss_load_t', ['station_count', 'available_capacity', 'channel_utilization'])
tim_t = namedtuple('tim_t', ['dtim_count', 'dtim_period', 'bitmap_control', 'partial_virtual_bitmap'])
vendor_specific_t = namedtuple('vendor_specific_t', ['oui', 'data'])

cdef class Dot11(PDU):
    """
    Base Dot11 packet
    """
    pdu_flag = PDU.DOT11
    pdu_type = PDU.DOT11
    datalink_type = DLT_IEEE802_11

    OptionTypes = IntEnum('OptionTypes', {
        "SSID": D11_SSID,
        "SUPPORTED_RATES": D11_SUPPORTED_RATES,
        "FH_SET": D11_FH_SET,
        "DS_SET": D11_DS_SET,
        "CF_SET": D11_CF_SET,
        "TIM": D11_TIM,
        "IBSS_SET": D11_IBSS_SET,
        "COUNTRY": D11_COUNTRY,
        "HOPPING_PATTERN_PARAMS": D11_HOPPING_PATTERN_PARAMS,
        "HOPPING_PATTERN_TABLE": D11_HOPPING_PATTERN_TABLE,
        "REQUEST_INFORMATION": D11_REQUEST_INFORMATION,
        "BSS_LOAD": D11_BSS_LOAD,
        "EDCA": D11_EDCA,
        "TSPEC": D11_TSPEC,
        "TCLAS": D11_TCLAS,
        "SCHEDULE": D11_SCHEDULE,
        "CHALLENGE_TEXT": D11_CHALLENGE_TEXT,
        "POWER_CONSTRAINT": D11_POWER_CONSTRAINT,
        "POWER_CAPABILITY": D11_POWER_CAPABILITY,
        "TPC_REQUEST": D11_TPC_REQUEST,
        "TPC_REPORT": D11_TPC_REPORT,
        "SUPPORTED_CHANNELS": D11_SUPPORTED_CHANNELS,
        "CHANNEL_SWITCH": D11_CHANNEL_SWITCH,
        "MEASUREMENT_REQUEST": D11_MEASUREMENT_REQUEST,
        "MEASUREMENT_REPORT": D11_MEASUREMENT_REPORT,
        "QUIET": D11_QUIET,
        "IBSS_DFS": D11_IBSS_DFS,
        "ERP_INFORMATION": D11_ERP_INFORMATION,
        "TS_DELAY": D11_TS_DELAY,
        "TCLAS_PROCESSING": D11_TCLAS_PROCESSING,
        "QOS_CAPABILITY": D11_QOS_CAPABILITY,
        "RSN": D11_RSN,
        "EXT_SUPPORTED_RATES": D11_EXT_SUPPORTED_RATES,
        "VENDOR_SPECIFIC": D11_VENDOR_SPECIFIC
    })

    ManagementSubtypes = IntEnum('ManagementSubtypes', {
        "ASSOC_REQ": D11_ASSOC_REQ,
        "ASSOC_RESP": D11_ASSOC_RESP,
        "REASSOC_REQ": D11_REASSOC_REQ,
        "REASSOC_RESP": D11_REASSOC_RESP,
        "PROBE_REQ": D11_PROBE_REQ,
        "PROBE_RESP": D11_PROBE_RESP,
        "BEACON": D11_BEACON,
        "ATIM": D11_ATIM,
        "DISASSOC": D11_DISASSOC,
        "AUTH": D11_AUTH,
        "DEAUTH": D11_DEAUTH
    })

    ControlSubtypes = IntEnum('ControlSubtypes', {
        "BLOCK_ACK_REQ": D11_BLOCK_ACK_REQ,
        "BLOCK_ACK": D11_BLOCK_ACK,
        "PS": D11_PS,
        "RTS": D11_RTS,
        "CTS": D11_CTS,
        "ACK": D11_ACK,
        "CF_END": D11_CF_END,
        "CF_END_ACK": D11_CF_END_ACK
    })

    DataSubtypes = IntEnum('DataSubtypes', {
        "DATA_DATA": D11_DATA_DATA,
        "DATA_CF_ACK": D11_DATA_CF_ACK,
        "DATA_CF_POLL": D11_DATA_CF_POLL,
        "DATA_CF_ACK_POLL": D11_DATA_CF_ACK_POLL,
        "DATA_NULL": D11_DATA_NULL,
        "CF_ACK": D11_CF_ACK,
        "CF_POLL": D11_CF_POLL,
        "CF_ACK_POLL": D11_CF_ACK_POLL,
        "QOS_DATA_DATA": D11_QOS_DATA_DATA,
        "QOS_DATA_CF_ACK": D11_QOS_DATA_CF_ACK,
        "QOS_DATA_CF_POLL": D11_QOS_DATA_CF_POLL,
        "QOS_DATA_CF_ACK_POLL": D11_QOS_DATA_CF_ACK_POLL,
        "QOS_DATA_NULL": D11_QOS_DATA_NULL
    })

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11:
            # object will be initialized later
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            self.ptr = new cppDot11(<cppHWAddress6> ((<HWAddress> dest).ptr[0]))

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        pass

    def __dealloc__(self):
        cdef cppDot11* p = <cppDot11*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL
        self.parent = None

    property protocol:
        def __get__(self):
            return <uint8_t> self.ptr.protocol()
        def __set__(self, value):
            self.ptr.protocol(small_uint2(<uint8_t> value))

    property type:
        def __get__(self):
            return <uint8_t> self.ptr.type()
        def __set__(self, value):
            self.ptr.type(small_uint2(<uint8_t> value))

    property subtype:
        def __get__(self):
            return <uint8_t> self.ptr.subtype()
        def __set__(self, value):
            self.ptr.subtype(small_uint4(<uint8_t> value))

    property to_ds:
        def __get__(self):
            return bool(<uint8_t> self.ptr.to_ds())
        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.to_ds(small_uint1(<uint8_t> value))

    property from_ds:
        def __get__(self):
            return bool(<uint8_t> self.ptr.from_ds())
        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.from_ds(small_uint1(<uint8_t> value))

    property more_frag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.more_frag())
        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.more_frag(small_uint1(<uint8_t> value))

    property retry:
        def __get__(self):
            return bool(<uint8_t> self.ptr.retry())
        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.retry(small_uint1(<uint8_t> value))

    property power_mgmt:
        def __get__(self):
            return bool(<uint8_t> self.ptr.power_mgmt())
        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.power_mgmt(small_uint1(<uint8_t> value))

    property wep:
        def __get__(self):
            return bool(<uint8_t> self.ptr.wep())
        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.wep(small_uint1(<uint8_t> value))

    property order:
        def __get__(self):
            return bool(<uint8_t> self.ptr.order())
        def __set__(self, value):
            value = 1 if value else 0
            self.ptr.order(small_uint1(<uint8_t> value))

    property duration_id:
        def __get__(self):
            return <uint16_t> self.ptr.duration_id()
        def __set__(self, value):
            self.ptr.duration_id(<uint16_t> value)

    property addr1:
        def __get__(self):
            return HWAddress(<bytes>(self.ptr.addr1().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            self.ptr.addr1((<HWAddress>value).ptr[0])

    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if sender is None:
            raise ValueError("sender can't be None")
        if iface is None:
            raise ValueError("iface can't be None")
        self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).ptr[0])

    @staticmethod
    def from_bytes(buf):
        if buf is None:
            return Dot11()
        cdef uint8_t* buf_addr
        cdef uint32_t size
        PDU.prepare_buf_arg(buf, &buf_addr, &size)
        return Dot11.c_from_bytes(buf_addr, size)

    @staticmethod
    cdef c_from_bytes(uint8_t* buf_addr, uint32_t size):
        if buf_addr is NULL or size == 0:
            return Dot11()
        cdef cppDot11* p = dot11_from_bytes(buf_addr, size)         # equivalent to new
        cdef string classname
        if p is not NULL:
            classname = map_pdutype_to_classname[p.pdu_type()]
            return (map_classname_to_factory[classname])(p, NULL, 0, None)
        else:
            raise MalformedPacket

cdef class Dot11Data(Dot11):
    """
    Base Dot11 packet
    """
    pdu_flag = PDU.DOT11_DATA
    pdu_type = PDU.DOT11_DATA

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11Data:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11Data(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11Data((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11.__init__(dest, src, buf, _raw)

    def __dealloc__(self):
        cdef cppDot11Data* p = <cppDot11Data*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL
        self.parent = None

    property addr2:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11Data*> self.ptr).addr2().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11Data*> self.ptr).addr2((<HWAddress> value).ptr[0])

    property addr3:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11Data*> self.ptr).addr3().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11Data*> self.ptr).addr3((<HWAddress> value).ptr[0])

    property addr4:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11Data*> self.ptr).addr4().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11Data*> self.ptr).addr4((<HWAddress> value).ptr[0])

    property frag_num:
        def __get__(self):
            return <uint8_t> ((<cppDot11Data*> self.ptr).frag_num())
        def __set__(self, value):
            (<cppDot11Data*> self.ptr).frag_num(small_uint4(<uint8_t> value))

    property seq_num:
        def __get__(self):
            return <uint16_t> ((<cppDot11Data*> self.ptr).seq_num())
        def __set__(self, value):
            (<cppDot11Data*> self.ptr).seq_num(small_uint12(<uint16_t> value))

    property src_addr:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11Data*> self.ptr).src_addr().to_string()))

    property dst_addr:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11Data*> self.ptr).dst_addr().to_string()))

    property bssid_addr:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11Data*> self.ptr).bssid_addr().to_string()))


cdef class Dot11QoSData(Dot11Data):
    pdu_flag = PDU.DOT11_QOS_DATA
    pdu_type = PDU.DOT11_QOS_DATA

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11QoSData:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11QoSData(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11QoSData((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11Data.__init__(dest, src, buf, _raw)

    def __dealloc__(self):
        cdef cppDot11QoSData* p = <cppDot11QoSData*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL
        self.parent = None

    property qos_control:
        def __get__(self):
            return int((<cppDot11QoSData*> self.ptr).qos_control())
        def __set__(self, value):
            (<cppDot11QoSData*> self.ptr).qos_control(<uint16_t> int(value))


cdef class Dot11ManagementFrame(Dot11):
    pdu_flag = PDU.DOT11_MANAGEMENT
    pdu_type = PDU.DOT11_MANAGEMENT

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        pass

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11.__init__(self, dest, src, buf, _raw)

    def __dealloc__(self):
        pass

    ReasonCodes = IntEnum('ReasonCodes', {
        'UNSPECIFIED': D11MGMT_UNSPECIFIED,
        'PREV_AUTH_NOT_VALID': D11MGMT_PREV_AUTH_NOT_VALID,
        'STA_LEAVING_IBSS_ESS': D11MGMT_STA_LEAVING_IBSS_ESS,
        'INACTIVITY': D11MGMT_INACTIVITY,
        'CANT_HANDLE_STA': D11MGMT_CANT_HANDLE_STA,
        'CLASS2_FROM_NO_AUTH': D11MGMT_CLASS2_FROM_NO_AUTH,
        'CLASS3_FROM_NO_AUTH': D11MGMT_CLASS3_FROM_NO_AUTH,
        'STA_LEAVING_BSS': D11MGMT_STA_LEAVING_BSS,
        'STA_NOT_AUTH_WITH_STA': D11MGMT_STA_NOT_AUTH_WITH_STA,
        'POW_CAP_NOT_VALID': D11MGMT_POW_CAP_NOT_VALID,
        'SUPPORTED_CHANN_NOT_VALID': D11MGMT_SUPPORTED_CHANN_NOT_VALID,
        'INVALID_CONTENT': D11MGMT_INVALID_CONTENT,
        'MIC_FAIL': D11MGMT_MIC_FAIL,
        'HANDSHAKE_TIMEOUT': D11MGMT_HANDSHAKE_TIMEOUT,
        'GROUP_KEY_TIMEOUT': D11MGMT_GROUP_KEY_TIMEOUT,
        'WRONG_HANDSHAKE': D11MGMT_WRONG_HANDSHAKE,
        'INVALID_GROUP_CIPHER': D11MGMT_INVALID_GROUP_CIPHER,
        'INVALID_PAIRWISE_CIPHER': D11MGMT_INVALID_PAIRWISE_CIPHER,
        'INVALID_AKMP': D11MGMT_INVALID_AKMP,
        'UNSOPPORTED_RSN_VERSION': D11MGMT_UNSOPPORTED_RSN_VERSION,
        'INVALID_RSN_CAPABILITIES': D11MGMT_INVALID_RSN_CAPABILITIES,
        'AUTH_FAILED': D11MGMT_AUTH_FAILED,
        'CIPHER_SUITE_REJECTED': D11MGMT_CIPHER_SUITE_REJECTED,
        'UNSPECIFIED_QOS_REASON': D11MGMT_UNSPECIFIED_QOS_REASON,
        'NOT_ENOUGH_BANDWITH': D11MGMT_NOT_ENOUGH_BANDWITH,
        'POOR_CHANNEL': D11MGMT_POOR_CHANNEL,
        'STA_OUT_OF_LIMITS': D11MGMT_STA_OUT_OF_LIMITS,
        'REQUESTED_BY_STA_LEAVING': D11MGMT_REQUESTED_BY_STA_LEAVING,
        'REQUESTED_BY_STA_REJECT_MECHANISM': D11MGMT_REQUESTED_BY_STA_REJECT_MECHANISM,
        'REQUESTED_BY_STA_REJECT_SETUP': D11MGMT_REQUESTED_BY_STA_REJECT_SETUP,
        'REQUESTED_BY_STA_TIMEOUT': D11MGMT_REQUESTED_BY_STA_TIMEOUT,
        'PEER_STA_NOT_SUPPORT_CIPHER': D11MGMT_PEER_STA_NOT_SUPPORT_CIPHER
    })

    property addr2:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11ManagementFrame*> self.ptr).addr2().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ManagementFrame*> self.ptr).addr2((<HWAddress> value).ptr[0])

    property addr3:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11ManagementFrame*> self.ptr).addr3().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ManagementFrame*> self.ptr).addr3((<HWAddress> value).ptr[0])

    property addr4:
        def __get__(self):
            return HWAddress(<bytes>((<cppDot11ManagementFrame*> self.ptr).addr4().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ManagementFrame*> self.ptr).addr4((<HWAddress> value).ptr[0])

    property ssid:
        def __get__(self):
            try:
                return <bytes> ((<cppDot11ManagementFrame*> self.ptr).ssid())
            except OptionNotFound:
                return None
        def __set__(self, value):
            if value is None:
                pass    # todo: delete option
            value = bytes(value)
            (<cppDot11ManagementFrame*> self.ptr).ssid(<string> value)

    property rsn_information:
        def __get__(self):
            cdef cppRSNInformation info
            try:
                info = (<cppDot11ManagementFrame*> self.ptr).rsn_information()
            except OptionNotFound:
                return None
            return RSNInformation.factory(&info)

        def __set__(self, info):
            if not isinstance(info, RSNInformation):
                info = RSNInformation(buf=info)
            (<cppDot11ManagementFrame*> self.ptr).rsn_information((<RSNInformation> info).ptr[0])

    property supported_rates:
        def __get__(self):
            try:
                return list((<cppDot11ManagementFrame*> self.ptr).supported_rates())
            except OptionNotFound:
                return None
        def __set__(self, values):
            cdef vector[float] rates = [float(rate) for rate in values]
            (<cppDot11ManagementFrame*> self.ptr).supported_rates(rates)

    property extended_supported_rates:
        def __get__(self):
            try:
                return list((<cppDot11ManagementFrame*> self.ptr).extended_supported_rates())
            except OptionNotFound:
                return None
        def __set__(self, values):
            cdef vector[float] rates = [float(rate) for rate in values]
            (<cppDot11ManagementFrame*> self.ptr).extended_supported_rates(rates)

    property qos_capability:
        def __get__(self):
            try:
                return (<cppDot11ManagementFrame*> self.ptr).qos_capability()
            except OptionNotFound:
                return None
        def __set__(self, value):
            (<cppDot11ManagementFrame*> self.ptr).qos_capability(<uint8_t> int(value))

    property power_capability:
        def __get__(self):
            try:
                return <tuple>((<cppDot11ManagementFrame*> self.ptr).power_capability())
            except OptionNotFound:
                return None
        def __set__(self, pair_values):
            (<cppDot11ManagementFrame*> self.ptr).power_capability(<uint8_t> int(pair_values[0]), <uint8_t> int(pair_values[1]))

    property supported_channels:
        def __get__(self):
            try:
                return [(p.first, p.second) for p in (<cppDot11ManagementFrame*> self.ptr).supported_channels()]
            except OptionNotFound:
                return None
        def __set__(self, channels):
            (<cppDot11ManagementFrame*> self.ptr).supported_channels(<vector[pair[uint8_t, uint8_t]]> channels)

    property request_information:
        def __get__(self):
            try:
                return <list> ((<cppDot11ManagementFrame*> self.ptr).request_information())
            except OptionNotFound:
                return None

        def __set__(self, elements):
            (<cppDot11ManagementFrame*> self.ptr).request_information(<vector[uint8_t]> elements)

    property fh_parameter_set:
        def __get__(self):
            cdef cppDot11ManagementFrame.fh_params_set s
            try:
                s = (<cppDot11ManagementFrame*> self.ptr).fh_parameter_set()
                return fh_params(s.dwell_time, s.hop_set, s.hop_pattern, s.hop_index)
            except OptionNotFound:
                return None
        def __set__(self, value):
            dwell_time, hop_set, hop_pattern, hop_index = value
            cdef cppDot11ManagementFrame.fh_params_set s = cppDot11ManagementFrame.fh_params_set(
                <uint16_t> dwell_time, <uint8_t> hop_set, <uint8_t> hop_pattern, <uint8_t> hop_index
            )
            (<cppDot11ManagementFrame*> self.ptr).fh_parameter_set(s)

    property ds_parameter_set:
        def __get__(self):
            try:
                return (<cppDot11ManagementFrame*> self.ptr).ds_parameter_set()
            except OptionNotFound:
                return None
        def __set__(self, value):
            (<cppDot11ManagementFrame*> self.ptr).ds_parameter_set(<uint8_t> int(value))

    property cf_parameter_set:
        def __get__(self):
            cdef cppDot11ManagementFrame.cf_params_set s
            try:
                s = (<cppDot11ManagementFrame*> self.ptr).cf_parameter_set()
                return cf_params(s.cfp_count, s.cfp_period, s.cfp_max_duration, s.cfp_dur_remaining)
            except OptionNotFound:
                return None
        def __set__(self, value):
            cfp_count, cfp_period, cfp_max_duration, cfp_dur_remaining = value
            cdef cppDot11ManagementFrame.cf_params_set s = cppDot11ManagementFrame.cf_params_set(
                <uint8_t> cfp_count, <uint8_t> cfp_period, <uint16_t> cfp_max_duration, <uint16_t> cfp_dur_remaining
            )
            (<cppDot11ManagementFrame*> self.ptr).cf_parameter_set(s)

    property ibss_parameter_set:
        def __get__(self):
            try:
                return (<cppDot11ManagementFrame*> self.ptr).ibss_parameter_set()
            except OptionNotFound:
                return None
        def __set__(self, value):
            (<cppDot11ManagementFrame*> self.ptr).ibss_parameter_set(<uint16_t> int(value))

    property ibss_dfs:
        def __get__(self):
            cdef cppDot11ManagementFrame.ibss_dfs_params p
            try:
                p = (<cppDot11ManagementFrame*> self.ptr).ibss_dfs()
            except OptionNotFound:
                return None
            dfs_owner = HWAddress(<bytes> (p.dfs_owner.to_string()))
            channel_map = [(int(apair.first), int(apair.second)) for apair in p.channel_map]
            return dfs_params(dfs_owner, int(p.recovery_interval), channel_map)

        def __set__(self, value):
            dfs_owner, recovery_interval, channel_map = value
            if not PyIter_Check(channel_map):
                raise ValueError("'channel_map' must be an iterable of (uint8, uint8)")
            if not isinstance(dfs_owner, HWAddress):
                dfs_owner = HWAddress(dfs_owner)
            recovery_interval = int(recovery_interval)
            cdef vector[pair[uint8_t, uint8_t]] channels
            cdef pair[uint8_t, uint8_t] apair
            for (x, y) in channel_map:
                apair.first = <uint8_t> int(x)
                apair.second = <uint8_t> int(y)
                channels.push_back(apair)
            cdef cppDot11ManagementFrame.ibss_dfs_params params = cppDot11ManagementFrame.ibss_dfs_params(
                (<HWAddress> dfs_owner).ptr[0], <uint8_t> recovery_interval, channels
            )
            (<cppDot11ManagementFrame*> self.ptr).ibss_dfs(params)

    property country:
        def __get__(self):
            cdef cppDot11ManagementFrame.country_params country_p
            try:
                country_p = (<cppDot11ManagementFrame*> self.ptr).country()
            except OptionNotFound:
                return None
            country_name = <bytes> country_p.country
            first_channel = <list> country_p.first_channel
            number_channels = <list> country_p.number_channels
            max_transmit_power = <list> country_p.max_transmit_power
            return country_params(country_name, first_channel, number_channels, max_transmit_power)

        def __set__(self, value):
            country_name, first_channel, number_channels, max_transmit_power = value
            if not PyIter_Check(first_channel):
                raise ValueError("'first_channel' must be an iterable of uint8")
            if not PyIter_Check(number_channels):
                raise ValueError("'number_channels' must be an iterable of uint8")
            if not PyIter_Check(max_transmit_power):
                raise ValueError("'max_transmit_power' must be an iterable of uint8")
            cdef vector[uint8_t] first_channel_v = first_channel
            cdef vector[uint8_t] number_channels_v = number_channels
            cdef vector[uint8_t] max_transmit_power_v = max_transmit_power
            cdef cppDot11ManagementFrame.country_params params = cppDot11ManagementFrame.country_params(
                <string> country_name, first_channel_v, number_channels_v, max_transmit_power_v
            )
            (<cppDot11ManagementFrame*> self.ptr).country(params)

    property fh_parameters:
        def __get__(self):
            cdef pair[uint8_t, uint8_t] apair
            try:
                apair = (<cppDot11ManagementFrame*> self.ptr).fh_parameters()
            except OptionNotFound:
                return None
            return apair.first, apair.second
        def __set__(self, value):
            first, second = value
            (<cppDot11ManagementFrame*> self.ptr).fh_parameters(<uint8_t> int(first), <uint8_t> int(second))

    property fh_pattern_table:
        def __get__(self):
            cdef cppDot11ManagementFrame.fh_pattern_type t
            try:
                t = (<cppDot11ManagementFrame*> self.ptr).fh_pattern_table()
            except OptionNotFound:
                return None
            random_table = <list> t.random_table
            return fh_pattern(int(t.flag), int(t.number_of_sets), int(t.modulus), int(t.offset), random_table)

        def __set__(self, value):
            flag, number_of_sets, modulus, offset, random_table = value
            if not PyIter_Check(random_table):
                raise ValueError("'random_table' must be an iterable of uint8")
            cdef vector[uint8_t] random_table_v = random_table
            cdef cppDot11ManagementFrame.fh_pattern_type t = cppDot11ManagementFrame.fh_pattern_type(
                <uint8_t> int(flag), <uint8_t> int(number_of_sets), <uint8_t> int(modulus), <uint8_t> int(offset), random_table_v
            )
            (<cppDot11ManagementFrame*> self.ptr).fh_pattern_table(t)

    property power_constraint:
        def __get__(self):
            try:
                return int((<cppDot11ManagementFrame*> self.ptr).power_constraint())
            except OptionNotFound:
                return None

        def __set__(self, value):
            (<cppDot11ManagementFrame*> self.ptr).power_constraint(<uint8_t>int(value))

    property channel_switch:
        def __get__(self):
            cdef cppDot11ManagementFrame.channel_switch_type c
            try:
                c = (<cppDot11ManagementFrame*> self.ptr).channel_switch()
            except OptionNotFound:
                return None
            return channel_switch_t(int(c.switch_mode), int(c.new_channel), int(c.switch_count))

        def __set__(self, value):
            switch_mode, new_channel, switch_count = value
            cdef cppDot11ManagementFrame.channel_switch_type c = cppDot11ManagementFrame.channel_switch_type(
                <uint8_t> int(switch_mode), <uint8_t> int(new_channel), <uint8_t> int(switch_count)
            )
            (<cppDot11ManagementFrame*> self.ptr).channel_switch(c)

    property quiet:
        def __get__(self):
            cdef cppDot11ManagementFrame.quiet_type q
            try:
                q = (<cppDot11ManagementFrame*> self.ptr).quiet()
            except OptionNotFound:
                return None
            return quiet_t(int(q.quiet_count), int(q.quiet_period), int(q.quiet_duration), int(q.quiet_offset))

        def __set__(self, value):
            quiet_count, quiet_period, quiet_duration, quiet_offset = value
            cdef cppDot11ManagementFrame.quiet_type q = cppDot11ManagementFrame.quiet_type(
                <uint8_t> int(quiet_count), <uint8_t> int(quiet_period), <uint16_t> int(quiet_duration), <uint16_t> int(quiet_offset)
            )
            (<cppDot11ManagementFrame*> self.ptr).quiet(q)

    property tpc_report:
        def __get__(self):
            cdef pair[uint8_t, uint8_t] apair
            try:
                apair = (<cppDot11ManagementFrame*> self.ptr).tpc_report()
            except OptionNotFound:
                return None
            return int(apair.first), int(apair.second)

        def __set__(self, value):
            first, second = value
            (<cppDot11ManagementFrame*> self.ptr).tpc_report(<uint8_t> int(first), <uint8_t> int(second))

    property erp_information:
        def __get__(self):
            try:
                return int((<cppDot11ManagementFrame*> self.ptr).erp_information())
            except OptionNotFound:
                return None

        def __set__(self, value):
            (<cppDot11ManagementFrame*> self.ptr).erp_information(<uint8_t> int(value))

    property bss_load:
        def __get__(self):
            cdef cppDot11ManagementFrame.bss_load_type bss
            try:
                bss = (<cppDot11ManagementFrame*> self.ptr).bss_load()
            except OptionNotFound:
                return None
            return bss_load_t(int(bss.station_count), int(bss.available_capacity), int(bss.channel_utilization))

        def __set__(self, value):
            station_count, available_capacity, channel_utilization = value
            cdef cppDot11ManagementFrame.bss_load_type bss = cppDot11ManagementFrame.bss_load_type(
                <uint16_t> int(station_count), <uint8_t> int(channel_utilization), <uint16_t> int(available_capacity)
            )
            (<cppDot11ManagementFrame*> self.ptr).bss_load(bss)

    property tim:
        def __get__(self):
            cdef cppDot11ManagementFrame.tim_type t
            try:
                t = (<cppDot11ManagementFrame*> self.ptr).tim()
            except OptionNotFound:
                return None
            bitmap = <list> t.partial_virtual_bitmap
            return int(t.dtim_count), int(t.dtim_period), int(t.bitmap_control), bitmap

        def __set__(self, value):
            dtim_count, dtim_period, bitmap_control, bitmap = value
            if not PyIter_Check(bitmap):
                raise ValueError("'bitmap' must be an iterable of uint8")
            cdef vector[uint8_t] bitmap_v = [int(x) for x in bitmap]
            cdef cppDot11ManagementFrame.tim_type t = cppDot11ManagementFrame.tim_type(
                <uint8_t> int(dtim_count), <uint8_t> int(dtim_period), <uint8_t> int(bitmap_control), bitmap_v
            )
            (<cppDot11ManagementFrame*> self.ptr).tim(t)

    property vendor_specific:
        def __get__(self):
            cdef cppDot11ManagementFrame.vendor_specific_type vendor
            try:
                vendor = (<cppDot11ManagementFrame*> self.ptr).vendor_specific()
            except OptionNotFound:
                return None
            addr = <bytes> (vendor.oui.to_string())
            data = <list> vendor.data
            return vendor_specific_t(addr, data)

        def __set__(self, value):
            cdef cppHWAddress3 addr = cppHWAddress3(<string> bytes(value[0]))
            cdef vector[uint8_t] data = [int(x) for x in value[1]]
            cdef cppDot11ManagementFrame.vendor_specific_type vendor = cppDot11ManagementFrame.vendor_specific_type(addr, data)
            (<cppDot11ManagementFrame*> self.ptr).vendor_specific(vendor)

    property challenge_text:
        def __get__(self):
            try:
                return <bytes>((<cppDot11ManagementFrame*> self.ptr).challenge_text())
            except OptionNotFound:
                return None

        def __set__(self, value):
            (<cppDot11ManagementFrame*> self.ptr).challenge_text(<string> bytes(value))


cdef class Capabilities(object):
    def __cinit__(self):
        pass

    def __init__(self):
        pass

    def __dealloc__(self):
        pass

    property ess:
        def __get__(self):
            return bool(self.cap_info.ess())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.ess(val)

    property ibss:
        def __get__(self):
            return bool(self.cap_info.ibss())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.ibss(val)

    property cf_poll:
        def __get__(self):
            return bool(self.cap_info.cf_poll())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.cf_poll(val)

    property cf_poll_req:
        def __get__(self):
            return bool(self.cap_info.cf_poll_req())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.cf_poll_req(val)

    property privacy:
        def __get__(self):
            return bool(self.cap_info.privacy())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.privacy(val)

    property short_preamble:
        def __get__(self):
            return bool(self.cap_info.short_preamble())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.short_preamble(val)

    property pbcc:
        def __get__(self):
            return bool(self.cap_info.pbcc())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.pbcc(val)

    property channel_agility:
        def __get__(self):
            return bool(self.cap_info.channel_agility())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.channel_agility(val)

    property spectrum_mgmt:
        def __get__(self):
            return bool(self.cap_info.spectrum_mgmt())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.spectrum_mgmt(val)

    property qos:
        def __get__(self):
            return bool(self.cap_info.qos())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.qos(val)

    property sst:
        def __get__(self):
            return bool(self.cap_info.sst())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.sst(val)

    property apsd:
        def __get__(self):
            return bool(self.cap_info.apsd())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.apsd(val)

    property reserved:
        def __get__(self):
            return bool(self.cap_info.reserved())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.reserved(val)

    property dsss_ofdm:
        def __get__(self):
            return bool(self.cap_info.dsss_ofdm())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.dsss_ofdm(val)

    property delayed_block_ack:
        def __get__(self):
            return bool(self.cap_info.delayed_block_ack())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.delayed_block_ack(val)

    property immediate_block_ack:
        def __get__(self):
            return bool(self.cap_info.immediate_block_ack())

        def __set__(self, value):
            cdef cpp_bool val = 1 if value else 0
            self.cap_info.immediate_block_ack(val)

cdef class Dot11Disassoc(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_DIASSOC
    pdu_type = PDU.DOT11_DIASSOC

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11Disassoc:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11Disassoc(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11Disassoc((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Disassoc* p = <cppDot11Disassoc*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property reason_code:
        def __get__(self):
            return int((<cppDot11Disassoc*> self.ptr).reason_code())

        def __set__(self, value):
            (<cppDot11Disassoc*> self.ptr).reason_code(<uint16_t> int(value))

cdef class Dot11AssocRequest(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_ASSOC_REQ
    pdu_type = PDU.DOT11_ASSOC_REQ

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11AssocRequest:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11AssocRequest(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11AssocRequest((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11AssocRequest* p = <cppDot11AssocRequest*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property listen_interval:
        def __get__(self):
            return int((<cppDot11AssocRequest*> self.ptr).listen_interval())

        def __set__(self, value):
            (<cppDot11AssocRequest*> self.ptr).listen_interval(<uint16_t> int(value))

    property capabilities:
        def __get__(self):
            return Capabilities.factory((<cppDot11AssocRequest*> self.ptr).capabilities())


cdef class Dot11AssocResponse(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_ASSOC_RESP
    pdu_type = PDU.DOT11_ASSOC_RESP

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11AssocResponse:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11AssocResponse(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11AssocResponse((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11AssocResponse* p = <cppDot11AssocResponse*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property status_code:
        def __get__(self):
            return int((<cppDot11AssocResponse*> self.ptr).status_code())

        def __set__(self, value):
            (<cppDot11AssocResponse*> self.ptr).status_code(<uint16_t> int(value))

    property aid:
        def __get__(self):
            return int((<cppDot11AssocResponse*> self.ptr).aid())

        def __set__(self, value):
            (<cppDot11AssocResponse*> self.ptr).aid(<uint16_t> int(value))

    property capabilities:
        def __get__(self):
            return Capabilities.factory((<cppDot11AssocResponse*> self.ptr).capabilities())


cdef class Dot11ReAssocRequest(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_REASSOC_REQ
    pdu_type = PDU.DOT11_REASSOC_REQ

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11ReAssocRequest:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11ReAssocRequest(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11ReAssocRequest((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11ReAssocRequest* p = <cppDot11ReAssocRequest*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property capabilities:
        def __get__(self):
            return Capabilities.factory((<cppDot11ReAssocRequest*> self.ptr).capabilities())

    property listen_interval:
        def __get__(self):
            return int((<cppDot11ReAssocRequest*> self.ptr).listen_interval())

        def __set__(self, value):
            (<cppDot11ReAssocRequest*> self.ptr).listen_interval(<uint16_t> int(value))

    property current_ap:
        def __get__(self):
            return HWAddress(<bytes> ((<cppDot11ReAssocRequest*> self.ptr).current_ap().to_string()))

        def __set__(self, value):
            if not(isinstance(value, HWAddress)):
                value = HWAddress(value)
            (<cppDot11ReAssocRequest*> self.ptr).current_ap((<HWAddress> value).ptr[0])


cdef class Dot11ReAssocResponse(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_REASSOC_RESP
    pdu_type = PDU.DOT11_REASSOC_RESP

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11ReAssocResponse:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11ReAssocResponse(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11ReAssocResponse((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11ReAssocResponse* p = <cppDot11ReAssocResponse*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property capabilities:
        def __get__(self):
            return Capabilities.factory((<cppDot11ReAssocResponse*> self.ptr).capabilities())

    property status_code:
        def __get__(self):
            return int((<cppDot11ReAssocResponse*> self.ptr).status_code())

        def __set__(self, value):
            (<cppDot11ReAssocResponse*> self.ptr).status_code(<uint16_t> int(value))

    property aid:
        def __get__(self):
            return int((<cppDot11ReAssocResponse*> self.ptr).aid())

        def __set__(self, value):
            (<cppDot11ReAssocResponse*> self.ptr).aid(<uint16_t> int(value))


cdef class Dot11Authentication(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_AUTH
    pdu_type = PDU.DOT11_AUTH

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11Authentication:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11Authentication(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11Authentication((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Authentication* p = <cppDot11Authentication*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property status_code:
        def __get__(self):
            return int((<cppDot11Authentication*> self.ptr).status_code())

        def __set__(self, value):
            (<cppDot11Authentication*> self.ptr).status_code(<uint16_t> int(value))

    property auth_algorithm:
        def __get__(self):
            return int((<cppDot11Authentication*> self.ptr).auth_algorithm())

        def __set__(self, value):
            (<cppDot11Authentication*> self.ptr).auth_algorithm(<uint16_t> int(value))

    property auth_seq_number:
        def __get__(self):
            return int((<cppDot11Authentication*> self.ptr).auth_seq_number())

        def __set__(self, value):
            (<cppDot11Authentication*> self.ptr).auth_seq_number(<uint16_t> int(value))


cdef class Dot11Deauthentication(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_DEAUTH
    pdu_type = PDU.DOT11_DEAUTH

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11Deauthentication:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11Deauthentication(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11Deauthentication((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Deauthentication* p = <cppDot11Deauthentication*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property reason_code:
        def __get__(self):
            return int((<cppDot11Deauthentication*> self.ptr).reason_code())

        def __set__(self, value):
            (<cppDot11Deauthentication*> self.ptr).reason_code(<uint16_t> int(value))


cdef class Dot11Beacon(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_BEACON
    pdu_type = PDU.DOT11_BEACON

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11Beacon:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11Beacon(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11Beacon((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Beacon* p = <cppDot11Beacon*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property timestamp:
        def __get__(self):
            return int((<cppDot11Beacon*> self.ptr).timestamp())

        def __set__(self, value):
            (<cppDot11Beacon*> self.ptr).timestamp(<uint64_t> int(value))

    property interval:
        def __get__(self):
            return int((<cppDot11Beacon*> self.ptr).interval())

        def __set__(self, value):
            (<cppDot11Beacon*> self.ptr).interval(<uint16_t> int(value))

    property capabilities:
        def __get__(self):
            return Capabilities.factory((<cppDot11Beacon*> self.ptr).capabilities())


cdef class Dot11ProbeRequest(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_PROBE_REQ
    pdu_type = PDU.DOT11_PROBE_REQ

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11ProbeRequest:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11ProbeRequest(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11ProbeRequest((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11ProbeRequest* p = <cppDot11ProbeRequest*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)


cdef class Dot11ProbeResponse(Dot11ManagementFrame):
    pdu_flag = PDU.DOT11_PROBE_RESP
    pdu_type = PDU.DOT11_PROBE_RESP

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11ProbeResponse:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11ProbeResponse(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11ProbeResponse((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11ProbeResponse* p = <cppDot11ProbeResponse*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11ManagementFrame.__init__(self, dest, src, buf, _raw)

    property timestamp:
        def __get__(self):
            return int((<cppDot11ProbeResponse*> self.ptr).timestamp())

        def __set__(self, value):
            (<cppDot11ProbeResponse*> self.ptr).timestamp(<uint64_t> int(value))

    property interval:
        def __get__(self):
            return int((<cppDot11ProbeResponse*> self.ptr).interval())

        def __set__(self, value):
            (<cppDot11ProbeResponse*> self.ptr).interval(<uint16_t> int(value))

    property capabilities:
        def __get__(self):
            return Capabilities.factory((<cppDot11ProbeResponse*> self.ptr).capabilities())


cdef class Dot11Control(Dot11):
    pdu_flag = PDU.DOT11_CONTROL
    pdu_type = PDU.DOT11_CONTROL

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):         # src is ignored
        if _raw:
            return
        if type(self) != Dot11Control:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11Control(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            self.ptr = new cppDot11Control((<HWAddress> dest).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Control* p = <cppDot11Control*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11.__init__(self, dest, src, buf, _raw)


cdef class Dot11RTS(Dot11Control):
    pdu_flag = PDU.DOT11_RTS
    pdu_type = PDU.DOT11_RTS

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11RTS:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11RTS(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11RTS((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11RTS* p = <cppDot11RTS*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11Control.__init__(self, dest, src, buf, _raw)

    property target_addr:
        def __get__(self):
            return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])

cdef class Dot11PSPoll(Dot11Control):
    pdu_flag = PDU.DOT11_PS_POLL
    pdu_type = PDU.DOT11_PS_POLL

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11PSPoll:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11PSPoll(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11PSPoll((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11PSPoll* p = <cppDot11PSPoll*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11Control.__init__(self, dest, src, buf, _raw)

    property target_addr:
        def __get__(self):
            return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])

cdef class Dot11CFEnd(Dot11Control):
    pdu_flag = PDU.DOT11_CF_END
    pdu_type = PDU.DOT11_CF_END

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11CFEnd:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11CFEnd(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11CFEnd((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11CFEnd* p = <cppDot11CFEnd*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11Control.__init__(self, dest, src, buf, _raw)

    property target_addr:
        def __get__(self):
            return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])

cdef class Dot11EndCFAck(Dot11Control):
    pdu_flag = PDU.DOT11_END_CF_ACK
    pdu_type = PDU.DOT11_END_CF_ACK

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11EndCFAck:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11EndCFAck(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11EndCFAck((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11EndCFAck* p = <cppDot11EndCFAck*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11Control.__init__(self, dest, src, buf, _raw)

    property target_addr:
        def __get__(self):
            return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])


cdef class Dot11Ack(Dot11Control):
    pdu_flag = PDU.DOT11_ACK
    pdu_type = PDU.DOT11_ACK

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11Ack:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11Ack(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            self.ptr = new cppDot11Ack((<HWAddress> dest).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11Ack* p = <cppDot11Ack*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11Control.__init__(self, dest, src, buf, _raw)

cdef class Dot11BlockAckRequest(Dot11Control):
    pdu_flag = PDU.DOT11_BLOCK_ACK_REQ
    pdu_type = PDU.DOT11_BLOCK_ACK_REQ

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11BlockAckRequest:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11BlockAckRequest(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11BlockAckRequest((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11BlockAckRequest* p = <cppDot11BlockAckRequest*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11Control.__init__(self, dest, src, buf, _raw)

    property target_addr:
        def __get__(self):
            return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])

    property bar_control:
        def __get__(self):
            return int(<uint8_t>((<cppDot11BlockAckRequest*> self.ptr).bar_control()))
        def __set__(self, value):
            (<cppDot11BlockAckRequest*> self.ptr).bar_control(small_uint4(<uint8_t>int(value)))

    property start_sequence:
        def __get__(self):
            return int(<uint16_t>((<cppDot11BlockAckRequest*> self.ptr).start_sequence()))
        def __set__(self, value):
            (<cppDot11BlockAckRequest*> self.ptr).start_sequence(small_uint12(<uint16_t>int(value)))

    property fragment_number:
        def __get__(self):
            return int(<uint8_t>((<cppDot11BlockAckRequest*> self.ptr).fragment_number()))
        def __set__(self, value):
            (<cppDot11BlockAckRequest*> self.ptr).fragment_number(small_uint4(<uint8_t>int(value)))


cdef class Dot11BlockAck(Dot11Control):
    pdu_flag = PDU.DOT11_BLOCK_ACK
    pdu_type = PDU.DOT11_BLOCK_ACK

    def __cinit__(self, dest=None, src=None, buf=None, _raw=False):
        if _raw:
            return
        if type(self) != Dot11BlockAck:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppDot11BlockAck(buf_addr, size)
        else:
            if not isinstance(dest, HWAddress):
                dest = HWAddress(dest)
            if not isinstance(src, HWAddress):
                src = HWAddress(src)
            self.ptr = new cppDot11BlockAck((<HWAddress> dest).ptr[0], (<HWAddress> src).ptr[0])

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        cdef cppDot11BlockAck* p = <cppDot11BlockAck*> self.ptr
        if self.ptr is not NULL and self.parent is None:
            del p
        self.ptr = NULL

    def __init__(self, dest=None, src=None, buf=None, _raw=False):
        Dot11Control.__init__(self, dest, src, buf, _raw)

    property target_addr:
        def __get__(self):
            return HWAddress(<bytes> ((<cppDot11ControlTA*> self.ptr).target_addr().to_string()))

        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            (<cppDot11ControlTA*> self.ptr).target_addr((<HWAddress> value).ptr[0])

    property bar_control:
        def __get__(self):
            return int(<uint8_t>((<cppDot11BlockAck*> self.ptr).bar_control()))
        def __set__(self, value):
            (<cppDot11BlockAck*> self.ptr).bar_control(small_uint4(<uint8_t>int(value)))

    property start_sequence:
        def __get__(self):
            return int(<uint16_t>((<cppDot11BlockAck*> self.ptr).start_sequence()))
        def __set__(self, value):
            (<cppDot11BlockAck*> self.ptr).start_sequence(small_uint12(<uint16_t>int(value)))

    property fragment_number:
        def __get__(self):
            return int(<uint8_t>((<cppDot11BlockAck*> self.ptr).fragment_number()))
        def __set__(self, value):
            (<cppDot11BlockAck*> self.ptr).fragment_number(small_uint4(<uint8_t>int(value)))

    property bitmap:
        def __get__(self):
            cdef uint8_t* b = <uint8_t*> ((<cppDot11BlockAck*> self.ptr).bitmap())
            return <bytes> b[:dot11_block_ack_bitmap_size]
        def __set__(self, value):
            value = bytes(value)[:dot11_block_ack_bitmap_size]
            (<cppDot11BlockAck*> self.ptr).bitmap(<uint8_t*>(<bytes>value))

