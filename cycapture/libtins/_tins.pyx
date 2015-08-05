# -*- coding: utf-8 -*-

# noinspection PyUnresolvedReferences
from cython.operator cimport dereference as deref
# noinspection PyUnresolvedReferences
from cython.operator cimport preincrement as inc

from .exceptions import LibtinsException, MalformedAddress, MalformedPacket, MalformedOption, OptionNotFound
from .exceptions import OptionPayloadTooLarge, FieldNotPresent, PDUNotFound, InvalidInterface, UnknownLinkType
from .exceptions import SocketOpenError, SocketCloseError, SocketWriteError, InvalidSocketType
from .exceptions import BadTinsCast, ProtocolDisabled

include "ipv4_address_pyx.pxi"
include "ipv6_address_pyx.pxi"
include "hw_address_pyx.pxi"
include "address_range_pyx.pxi"
include "networkinterface_pyx.pxi"
include "utils_pyx.pxi"
include "pdu_pyx.pxi"
include "ethernet_pyx.pxi"
include "ip_pyx.pxi"
include "tcp_pyx.pxi"
include "udp_pyx.pxi"
include "raw_pyx.pxi"
include "dns_pyx.pxi"

