# -*- coding: utf-8 -*-

cdef class RadioTap(PDU):
    """
    Ethernet packet
    """
    pdu_flag = PDU.RADIOTAP
    pdu_type = PDU.RADIOTAP
    broadcast = HWAddress.broadcast
    datalink_type = DLT_IEEE802_11_RADIO

    ChannelType = IntEnum('ChannelType', {
        'TURBO': RT_TURBO,
        'CCK': RT_CCK,
        'OFDM': RT_OFDM,
        'TWO_GZ': RT_TWO_GZ,
        'FIVE_GZ': RT_FIVE_GZ,
        'PASSIVE': RT_PASSIVE,
        'DYN_CCK_OFDM': RT_DYN_CCK_OFDM,
        'GFSK': RT_GFSK
    })

    PresentFlags = IntEnum('PresentFlags', {
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

    FrameFlags = IntEnum('FrameFlags', {
        'CFP': RT_CFP,
        'PREAMBLE': RT_PREAMBLE,
        'WEP': RT_WEP,
        'FRAGMENTATION': RT_FRAGMENTATION,
        'FCS': RT_FCS,
        'PADDING': RT_PADDING,
        'FAILED_FCS': RT_FAILED_FCS,
        'SHORT_GI': RT_SHORT_GI
    })

    def __cinit__(self, buf=None, _raw=False):
        if _raw:
            return
        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is None:
            self.ptr = new cppRadioTap()
        else:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppRadioTap(buf_addr, size)

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, buf=None, _raw=False):
        pass

    cpdef send(self, PacketSender sender, NetworkInterface iface):
        if sender is None:
            raise ValueError("sender can't be None")
        if iface is None:
            raise ValueError("iface can't be None")
        self.ptr.send((<PacketSender> sender).ptr[0], (<NetworkInterface> iface).ptr[0])

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
            return self.ptr.tsft()

        def __set__(self, value):
            self.ptr.tsft(<uint64_t> int(value))

    property rate:
        def __get__(self):
            return self.ptr.rate()

        def __set__(self, value):
            self.ptr.rate(<uint8_t> int(value))

    property dbm_signal:
        def __get__(self):
            return self.ptr.dbm_signal()

        def __set__(self, value):
            self.ptr.dbm_signal(<uint8_t> int(value))

    property dbm_noise:
        def __get__(self):
            return self.ptr.dbm_noise()

        def __set__(self, value):
            self.ptr.dbm_noise(<uint8_t> int(value))

    property signal_quality:
        def __get__(self):
            return self.ptr.signal_quality()

        def __set__(self, value):
            self.ptr.signal_quality(<uint8_t> int(value))

    property antenna:
        def __get__(self):
            return self.ptr.antenna()

        def __set__(self, value):
            self.ptr.antenna(<uint8_t> int(value))

    property db_signal:
        def __get__(self):
            return self.ptr.db_signal()

        def __set__(self, value):
            self.ptr.db_signal(<uint8_t> int(value))

    property rx_flags:
        def __get__(self):
            return self.ptr.rx_flags()

        def __set__(self, value):
            self.ptr.rx_flags(<uint16_t> int(value))

    property tx_flags:
        def __get__(self):
            return self.ptr.tx_flags()

        def __set__(self, value):
            self.ptr.tx_flags(<uint16_t> int(value))

    property data_retries:
        def __get__(self):
            return self.ptr.data_retries()

        def __set__(self, value):
            self.ptr.data_retries(<uint8_t> int(value))

    property flags:
        def __get__(self):
            return int(self.ptr.flags())

        def __set__(self, value):
            if isinstance(value, RadioTap.FrameFlags):
                value = value.value
            value = int(value)
            self.ptr.flags(<RTFrameFlags> value)

    property channel_freq:
        def __get__(self):
            return self.ptr.channel_freq()

    property channel_type:
        def __get__(self):
            return self.ptr.channel_type()

    property channel_plus:
        def __get__(self):
            return self.ptr.channel_plus()

    cpdef channel(self, new_freq, new_type):
        if new_freq is None:
            raise ValueError("new_freq can't be None")
        if new_type is None:
            raise ValueError("new_type can't be None")
        if isinstance(new_type, RadioTap.ChannelType):
            new_type = new_type.value
        self.ptr.channel(<uint16_t> int(new_freq), <uint16_t> int(new_type))

    property present:
        def __get__(self):
            return int(self.ptr.present())

    property mcs:
        def __get__(self):
            cdef mcs_type t = self.ptr.mcs()
            return t.known, t.flags, t.mcs

        def __set__(self, tuple_value):
            _known, _flags, _mcs = tuple_value
            cdef mcs_type t
            t.known = <uint8_t> _known
            t.flags = <uint8_t> _flags
            t.mcs = <uint8_t> _mcs
            self.ptr.mcs(t)



