# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, IPv4Address, ARP, PPI, Dot11Data

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"


def _f(packet):
    return "".join(chr(i) for i in packet)

packet1 = _f([
    0, 0, 84, 0, 105, 0, 0, 0, 2, 0, 20, 0, 99, 126, 205, 243, 0, 0, 0,
    0, 1, 0, 88, 2, 118, 9, 192, 0, 0, 0, 200, 160, 4, 0, 48, 0, 6, 0,
    0, 0, 2, 0, 0, 0, 0, 15, 2, 40, 34, 34, 30, 255, 36, 39, 33, 255,
    138, 9, 192, 0, 194, 160, 194, 160, 190, 160, 128, 128, 22, 17, 19,
    29, 21, 17, 23, 22, 25, 18, 26, 22, 0, 0, 0, 0, 136, 1, 44, 0, 0,
    20, 165, 205, 116, 123, 0, 20, 165, 203, 110, 26, 0, 1, 2, 39, 249,
    178, 160, 237, 0, 0, 170, 170, 3, 0, 0, 0, 8, 0, 69, 0, 0, 59, 141,
    6, 0, 0, 128, 17, 41, 214, 192, 168, 1, 132, 192, 168, 1, 1, 4, 7,
    0, 53, 0, 39, 171, 21, 150, 193, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3,
    119, 119, 119, 6, 112, 111, 108, 105, 116, 111, 2, 105, 116, 0, 0,
    1, 0, 1, 120, 128, 89, 55
])

class PPITest(unittest.TestCase):
    def test_constr_buff(self):
        ppi = PPI.from_buffer(packet1)
        eq_(ppi.version, 0)
        eq_(ppi.flags, 0)
        eq_(ppi.length, 84)
        eq_(ppi.dlt, 105)
        ppi.rfind_pdu(Dot11Data)
        ppi.rfind_pdu(UDP)
