# -*- coding: utf-8 -*-

"""
libtins bindings using cython
"""

__author__ = 'stef'

# specific exceptions (they all inherit from LibtinsException)

from ._tins import LibtinsException, MalformedAddress, MalformedPacket, MalformedOption, OptionNotFound
from ._tins import OptionPayloadTooLarge, FieldNotPresent, PDUNotFound, InvalidInterface, UnknownLinkType
from ._tins import SocketOpenError, SocketCloseError, SocketWriteError, InvalidSocketType, BadTinsCast, ProtocolDisabled

# addresses and ranges
from ._tins import IPv4Address, IPv6Address, HWAddress, IPv4Range, IPv6Range, HWRange, NetworkInterface

# abstract PDU
from ._tins import PDU, factory_PDU_from_typed_memoryview

# concrete PDUs
from ._tins import EthernetII, IP, TCP, UDP, Raw
from ._tins import DNS, DNS_Query, DNS_Resource

# utils
from ._tins import RouteEntry, get_route_entries, list_network_interfaces, pdutype_to_string
