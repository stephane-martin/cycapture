# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from cython.operator cimport dereference as deref
# noinspection PyUnresolvedReferences
from cython.operator cimport preincrement as inc

from enum import Enum, IntEnum
from collections import namedtuple
import inspect

from ._py_exceptions import LibtinsException, MalformedAddress, MalformedPacket, MalformedOption, OptionNotFound
from ._py_exceptions import OptionPayloadTooLarge, FieldNotPresent, PDUNotFound, InvalidInterface, UnknownLinkType
from ._py_exceptions import SocketOpenError, SocketCloseError, SocketWriteError, InvalidSocketType, BadTinsCast
from ._py_exceptions import ProtocolDisabled, MemoryViewFormat

def make_enum(typename, label, docstring, values):
    cls = IntEnum(typename, values)
    cls.__name__ = label
    cls.__doc__ = docstring + "\n\nAttributes: " + ", ".join(['``{}``'.format(attr) for attr in cls.__members__.keys()])
    return cls

include "constants_pyx.pxi"
include "ipv4_address_pyx.pxi"
include "ipv6_address_pyx.pxi"
include "hw_address_pyx.pxi"
include "address_range_pyx.pxi"
include "networkinterface_pyx.pxi"
include "utils_pyx.pxi"
include "rsn_pyx.pxi"
include "pdu_pyx.pxi"
include "ethernet_pyx.pxi"
include "ip_pyx.pxi"
include "tcp_pyx.pxi"
include "udp_pyx.pxi"
include "raw_pyx.pxi"
include "dns_pyx.pxi"
include "icmp_pyx.pxi"
include "radiotap_pyx.pxi"
include "arp_pyx.pxi"
include "dot3_pyx.pxi"
include "bootp_pyx.pxi"
include "dhcp_pyx.pxi"
include "dot1q_pyx.pxi"
include "loopback_pyx.pxi"
include "llc_pyx.pxi"
include "dot11_pyx.pxi"
include "snap_pyx.pxi"
include "eapol_pyx.pxi"
include "stp_pyx.pxi"
include "sll_pyx.pxi"
include "pppoe_pyx.pxi"
include "pktap_pyx.pxi"
include "ppi_pyx.pxi"
include "ipsec_pyx.pxi"
include "ipv4_reassembler_pyx.pxi"
include "packet_sender_pyx.pxi"
include "tcp_stream_pyx.pxi"
include "tcp_stream_follower_pyx.pxi"
