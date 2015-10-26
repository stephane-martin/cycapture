# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true

# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound, DNS, SNAP
# noinspection PyUnresolvedReferences
from .._tins import DNS_Query, DNS_Resource

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

expected_packet = _f([
    170, 170, 3, 0, 0, 1, 8, 0
])

class SNAPTest(unittest.TestCase):
    def check_equals(self, snap1, snap2):
        eq_(snap1.dsap, snap2.dsap)
        eq_(snap1.ssap, snap2.ssap)
        eq_(snap1.control, snap2.control)
        eq_(snap1.eth_type, snap2.eth_type)

    def test_default_constr(self):
        snap = SNAP()
        eq_(snap.pdu_type, PDU.SNAP)
        eq_(snap.dsap, 0xaa)
        eq_(snap.ssap, 0xaa)
        eq_(snap.eth_type, 0)
        eq_(snap.org_code, 0)
        eq_(snap.control, 3)

    def test_copy(self):
        snap1 = SNAP()
        snap1.eth_type = 0xfab1
        snap1.org_code = 0xfab1c3
        snap1.control = 0x1

        snap2 = snap1.copy()
        self.check_equals(snap1, snap2)

    def test_org_code(self):
        snap = SNAP()
        snap.org_code = 0xfab1c3
        eq_(snap.org_code, 0xfab1c3)
        eq_(snap.control, 3)

    def test_control(self):
        snap = SNAP()
        snap.control = 0xfa
        eq_(snap.control, 0xfa)
        eq_(snap.org_code, 0)

    def test_ethtype(self):
        snap = SNAP()
        snap.eth_type = 0xfab1
        eq_(snap.eth_type, 0xfab1)

    def test_serialize(self):
        snap1 = SNAP()
        snap1.eth_type = 0xfab1
        snap1.org_code = 0xfab1c3
        snap1.control = 0x1

        buf = snap1.serialize()
        snap2 = snap1.copy()
        buf2 = snap2.serialize()
        eq_(buf, buf2)

    def test_clone(self):
        snap1 = SNAP()
        snap1.eth_type = 0xfab1
        snap1.org_code = 0xfab1c3
        snap1.control = 0x1
        self.check_equals(snap1.copy(), snap1)

    def test_constr_buf(self):
        snap1 = SNAP.from_buffer(expected_packet)
        buf = snap1.serialize()
        eq_(snap1.control, 3)
        eq_(snap1.dsap, 0xaa)
        eq_(snap1.ssap, 0xaa)
        eq_(snap1.eth_type, 0x0800)
        eq_(snap1.org_code, 1)
        snap2 = SNAP.from_buffer(buf)
        self.check_equals(snap1, snap2)


