# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true

# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound, DNS, SNAP, SLL
# noinspection PyUnresolvedReferences
from .._tins import DNS_Query, DNS_Resource

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

expected_packet = _f([
    0, 0, 0, 1, 0, 6, 0, 27, 17, 210, 27, 235, 0, 0, 8, 0, 69, 0, 0, 116,
    65, 18, 0, 0, 44, 6, 156, 54, 173, 194, 66, 109, 192, 168, 0, 100,
    3, 225, 141, 4, 55, 61, 150, 161, 85, 106, 73, 189, 128, 24, 1, 0,
    202, 119, 0, 0, 1, 1, 8, 10, 71, 45, 40, 171, 0, 19, 78, 86, 23, 3,
    1, 0, 59, 168, 147, 182, 150, 159, 178, 204, 116, 62, 85, 80, 167,
    23, 24, 173, 236, 55, 46, 190, 205, 255, 19, 248, 129, 198, 140, 208,
    60, 79, 59, 38, 165, 131, 33, 105, 212, 112, 174, 80, 211, 48, 37,
    116, 108, 109, 33, 36, 231, 154, 131, 112, 246, 3, 180, 199, 158, 205,
    123, 238
])

class SLLTest(unittest.TestCase):
    def test_default_constr(self):
        sll = SLL()
        eq_(sll.packet_type, 0)
        eq_(sll.lladdr_type, 0)
        eq_(sll.lladdr_len, 0)
        eq_(sll.protocol, 0)
        eq_(sll.address, "00:00:00:00:00:00:00:00")

    def test_constr_buffer(self):
        addr = HWAddress("00:1b:11:d2:1b:eb")
        sll = SLL.from_buffer(expected_packet)
        eq_(sll.packet_type, 0)
        eq_(sll.lladdr_type, 1)
        eq_(sll.lladdr_len, 6)
        eq_(sll.protocol, 0x0800)
        eq_(sll.address, addr)
        assert_true(sll.ref_inner_pdu() is not None)
        assert_true(sll.rfind_pdu(IP) is not None)

    def test_serialize(self):
        sll = SLL.from_buffer(expected_packet)
        buf = sll.serialize()
        eq_(len(expected_packet), len(buf))
        eq_(expected_packet, buf)

    def test_packet_type(self):
        sll = SLL()
        sll.packet_type = 0x923f
        eq_(sll.packet_type, 0x923f)

    def test_lladdrtype(self):
        sll = SLL()
        sll.lladdr_type = 0x923f
        eq_(sll.lladdr_type, 0x923f)

    def test_lladdrlen(self):
        sll = SLL()
        sll.lladdr_len = 0x923f
        eq_(sll.lladdr_len, 0x923f)

    def test_protocol(self):
        sll = SLL()
        sll.protocol = 0x923f
        eq_(sll.protocol, 0x923f)

    def test_address(self):
        addr = HWAddress("00:01:02:03:04:05")
        sll = SLL()
        sll.address = addr
        eq_(sll.address, addr)

