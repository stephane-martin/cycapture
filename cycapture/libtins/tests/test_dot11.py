# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound, DNS, DHCP, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

