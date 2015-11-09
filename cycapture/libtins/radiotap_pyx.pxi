# -*- coding: utf-8 -*-

cdef class RadioTap(PDU):
    """
    RadioTap packet
    """
    pdu_flag = PDU.RADIOTAP
    pdu_type = PDU.RADIOTAP
    broadcast = HWAddress.broadcast
    datalink_type = DLT_IEEE802_11_RADIO

    ChannelType = make_enum('RT_ChannelType', 'ChannelType', 'Enumeration of the different channel types. See `RadioTap.channel`.', {
        'TURBO': RT_TURBO,
        'CCK': RT_CCK,
        'OFDM': RT_OFDM,
        'TWO_GZ': RT_TWO_GZ,
        'FIVE_GZ': RT_FIVE_GZ,
        'PASSIVE': RT_PASSIVE,
        'DYN_CCK_OFDM': RT_DYN_CCK_OFDM,
        'GFSK': RT_GFSK
    })

    PresentFlags = make_enum('RT_PresentFlags', 'PresentFlags', 'Flags used in the `RadioTap.present` property', {
        'TSTF': RT_TSTF,
        'FLAGS': RT_FLAGS,
        'RATE': RT_RATE,
        'CHANNEL': RT_CHANNEL,
        'FHSS': RT_FHSS,
        'DBM_SIGNAL': RT_DBM_SIGNAL,
        'DBM_NOISE': RT_DBM_NOISE,
        'LOCK_QUALITY': RT_LOCK_QUALITY,
        'TX_ATTENUATION': RT_TX_ATTENUATION,
        'DB_TX_ATTENUATION': RT_DB_TX_ATTENUATION,
        'DBM_TX_ATTENUATION': RT_DBM_TX_ATTENUATION,
        'ANTENNA': RT_ANTENNA,
        'DB_SIGNAL': RT_DB_SIGNAL,
        'DB_NOISE': RT_DB_NOISE,
        'RX_FLAGS': RT_RX_FLAGS,
        'TX_FLAGS': RT_TX_FLAGS,
        'DATA_RETRIES': RT_DATA_RETRIES,
        'CHANNEL_PLUS': RT_CHANNEL_PLUS,
        'MCS': RT_MCS
    })

    FrameFlags = make_enum('RT_FrameFlags', 'FrameFlags', 'Flags used in the `RadioTap.flags` property', {
        'CFP': RT_CFP,
        'PREAMBLE': RT_PREAMBLE,
        'WEP': RT_WEP,
        'FRAGMENTATION': RT_FRAGMENTATION,
        'FCS': RT_FCS,
        'PADDING': RT_PADDING,
        'FAILED_FCS': RT_FAILED_FCS,
        'SHORT_GI': RT_SHORT_GI
    })

    def __cinit__(self, _raw=False):
        if _raw:
            return
        self.ptr = new cppRadioTap()
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self):
        """
        __init__()
        """

    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if sender is None:
            raise ValueError("sender can't be None")
        if iface is None:
            raise ValueError("iface can't be None")
        self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).interface)

    property version:
        def __get__(self):
            return self.ptr.version()

        def __set__(self, value):
            self.ptr.version(<uint8_t> int(value))

    property padding:
        def __get__(self):
            return self.ptr.padding()

        def __set__(self, value):
            self.ptr.padding(<uint8_t> int(value))

    property length:
        def __get__(self):
            return self.ptr.length()

        def __set__(self, value):
            self.ptr.length(<uint16_t> int(value))

    property tsft:
        def __get__(self):
            try:
                return self.ptr.tsft()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.tsft(<uint64_t> int(value))

    property rate:
        def __get__(self):
            try:
                return self.ptr.rate()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.rate(<uint8_t> int(value))

    property dbm_signal:
        def __get__(self):
            try:
                return self.ptr.dbm_signal()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.dbm_signal(<uint8_t> int(value))

    property dbm_noise:
        def __get__(self):
            try:
                return self.ptr.dbm_noise()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.dbm_noise(<uint8_t> int(value))

    property signal_quality:
        def __get__(self):
            try:
                return self.ptr.signal_quality()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.signal_quality(<uint8_t> int(value))

    property antenna:
        def __get__(self):
            try:
                return self.ptr.antenna()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.antenna(<uint8_t> int(value))

    property db_signal:
        def __get__(self):
            try:
                return self.ptr.db_signal()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.db_signal(<uint8_t> int(value))

    property rx_flags:
        def __get__(self):
            try:
                return self.ptr.rx_flags()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.rx_flags(<uint16_t> int(value))

    property tx_flags:
        def __get__(self):
            try:
                return self.ptr.tx_flags()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.tx_flags(<uint16_t> int(value))

    property data_retries:
        def __get__(self):
            try:
                return self.ptr.data_retries()
            except FieldNotPresent:
                return None

        def __set__(self, value):
            self.ptr.data_retries(<uint8_t> int(value))

    property flags:
        def __get__(self):
            try:
                return int(self.ptr.flags())
            except FieldNotPresent:
                return None

        def __set__(self, value):
            value = int(value)
            self.ptr.flags(<RTFrameFlags> value)

    property channel_freq:
        def __get__(self):
            try:
                return self.ptr.channel_freq()
            except FieldNotPresent:
                return None

    property channel_type:
        def __get__(self):
            try:
                return self.ptr.channel_type()
            except FieldNotPresent:
                return None

    property channel_plus:
        def __get__(self):
            try:
                return self.ptr.channel_plus()
            except FieldNotPresent:
                return None

    cpdef channel(self, new_freq, new_type):
        """
        channel(self, new_freq, new_type)
        Setter for the channel frequency and type field

        Parameters
        ----------
        new_freq: uint16_t
            The new channel frequency
        new_type: uint16_t
            The new channel type (you can OR the `ChannelType` values)
        Returns
        -------

        """
        if new_freq is None:
            raise ValueError("new_freq can't be None")
        if new_type is None:
            raise ValueError("new_type can't be None")
        self.ptr.channel(<uint16_t> int(new_freq), <uint16_t> int(new_type))

    property present:
        """
        Return which fields are set. You can mask this value using the PresentFlags enum. (read-only property)
        """
        def __get__(self):
            return int(self.ptr.present())

    property mcs:
        """
        the MCS field (read-write, ``uint8_t``)
        """
        def __get__(self):
            cdef mcs_type t
            try:
                t = self.ptr.mcs()
                return t.known, t.flags, t.mcs
            except FieldNotPresent:
                return None

        def __set__(self, tuple_value):
            _known, _flags, _mcs = tuple_value
            cdef mcs_type t
            t.known = <uint8_t> _known
            t.flags = <uint8_t> _flags
            t.mcs = <uint8_t> _mcs
            self.ptr.mcs(t)

    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppRadioTap(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppRadioTap*> ptr

Radiotap = RadioTap
