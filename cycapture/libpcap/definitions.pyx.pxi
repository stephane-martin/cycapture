# -*- coding: utf-8 -*-

DLT = None
DIRECTION = None

cdef _make_enums():
    global DLT, DIRECTION
    DLT = make_enum('DLT', 'DLT', 'Datalink types', {
        'DLT_NULL': DLT_NULL,
        'DLT_EN10MB': DLT_EN10MB,
        'DLT_EN3MB': DLT_EN3MB,
        'DLT_AX25': DLT_AX25,
        'DLT_PRONET': DLT_PRONET,
        'DLT_CHAOS': DLT_CHAOS,
        'DLT_IEEE802': DLT_IEEE802,
        'DLT_ARCNET': DLT_ARCNET,
        'DLT_SLIP': DLT_SLIP,
        'DLT_PPP': DLT_PPP,
        'DLT_FDDI': DLT_FDDI,
        'DLT_RAW': DLT_RAW,
        'DLT_IEEE802_11': DLT_IEEE802_11,
        'DLT_LOOP': DLT_LOOP,
        'DLT_ENC': DLT_ENC,
        'DLT_PRISM_HEADER': DLT_PRISM_HEADER,
        'DLT_AIRONET_HEADER': DLT_AIRONET_HEADER,
        'DLT_IEEE802_11_RADIO': DLT_IEEE802_11_RADIO,
        'DLT_IEEE802_11_RADIO_AVS': DLT_IEEE802_11_RADIO_AVS,
        'DLT_IPV4': DLT_IPV4,
        'DLT_IPV6': DLT_IPV6
    })

    DIRECTION = make_enum('DIRECTION', 'DIRECTION', 'Sniffing direction', {
        'PCAP_D_INOUT': PCAP_D_INOUT,
        'PCAP_D_IN': PCAP_D_IN,
        'PCAP_D_OUT': PCAP_D_OUT
    })

_make_enums()

