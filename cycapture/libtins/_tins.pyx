# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from cython.operator cimport dereference as deref
# noinspection PyUnresolvedReferences
from cython.operator cimport preincrement as inc

from enum import Enum, IntEnum
from collections import namedtuple

from ._py_exceptions import LibtinsException, MalformedAddress, MalformedPacket, MalformedOption, OptionNotFound
from ._py_exceptions import OptionPayloadTooLarge, FieldNotPresent, PDUNotFound, InvalidInterface, UnknownLinkType
from ._py_exceptions import SocketOpenError, SocketCloseError, SocketWriteError, InvalidSocketType, BadTinsCast
from ._py_exceptions import ProtocolDisabled, MemoryViewFormat

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
include "dot11_pyx.pxi"
include "ipv4_reassembler_pyx.pxi"
include "packet_sender_pyx.pxi"
include "tcp_stream_pyx.pxi"
include "tcp_stream_follower_pyx.pxi"
