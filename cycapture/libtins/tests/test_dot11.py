# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, Dot11, RAW, PDUNotFound, UDP, OptionNotFound, DNS, DHCP, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

empty_addr = HWAddress()
addr = HWAddress("72:91:34:fa:de:ad")
expected_packet = _f([53, 1, 79, 35, 0, 1, 2, 3, 4, 5])

class Dot11Test(unittest.TestCase):
    def check_equals(self, dot1, dot2):
        eq_(dot1.protocol, dot2.protocol)
        eq_(dot1.type, dot2.type)
        eq_(dot1.subtype, dot2.subtype)
        eq_(dot1.to_ds, dot2.to_ds)
        eq_(dot1.from_ds, dot2.from_ds)
        eq_(dot1.more_frag, dot2.more_frag)
        eq_(dot1.retry, dot2.retry)
        eq_(dot1.power_mgmt, dot2.power_mgmt)
        eq_(dot1.wep, dot2.wep)
        eq_(dot1.order, dot2.order)
        eq_(dot1.duration_id, dot2.duration_id)
        eq_(dot1.addr1, dot2.addr1)

    def check_empty(self, dot1):
        empty = HWAddress()
        eq_(dot1.protocol, 0)
        eq_(dot1.to_ds, 0)
        eq_(dot1.from_ds, 0)
        eq_(dot1.more_frag, 0)
        eq_(dot1.retry, 0)
        eq_(dot1.power_mgmt, 0)
        eq_(dot1.wep, 0)
        eq_(dot1.order, 0)
        eq_(dot1.duration_id, 0)
        eq_(dot1.addr1, empty)

    def test_default_constr(self):
        dot = Dot11()
        eq_(dot.protocol, 0)
        eq_(dot.type, 0)
        eq_(dot.subtype, 0)
        eq_(dot.to_ds, 0)
        eq_(dot.from_ds, 0)
        eq_(dot.more_frag, 0)
        eq_(dot.retry, 0)
        eq_(dot.power_mgmt, 0)
        eq_(dot.wep, 0)
        eq_(dot.order, 0)
        eq_(dot.duration_id, 0)
        eq_(dot.addr1, empty_addr)

    def test_copy(self):
        dot1 = Dot11.from_buffer(expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_constr_buf(self):
        dot = Dot11.from_buffer(expected_packet)
        eq_(dot.protocol, 1)
        eq_(dot.type, Dot11.Types.CONTROL)
        eq_(dot.subtype, 3)
        eq_(dot.to_ds, 1)
        eq_(dot.from_ds, 0)
        eq_(dot.more_frag, 0)
        eq_(dot.retry, 0)
        eq_(dot.power_mgmt, 0)
        eq_(dot.wep, 0)
        eq_(dot.order, 0)
        eq_(dot.duration_id, 0x234f)
        eq_(dot.addr1, "00:01:02:03:04:05")

    def test_src_addr_constr(self):
        dot = Dot11(addr)
        eq_(dot.addr1, addr)

    def test_protocol(self):
        dot = Dot11()
        dot.protocol = 1
        eq_(dot.protocol, 1)

    def test_type(self):
        dot = Dot11()
        dot.type = Dot11.Types.CONTROL
        eq_(dot.type, Dot11.Types.CONTROL)

    def test_subtype(self):
        dot = Dot11()
        dot.subtype = Dot11.DataSubtypes.QOS_DATA_DATA
        eq_(dot.subtype, Dot11.DataSubtypes.QOS_DATA_DATA)

    def test_to_ds(self):
        dot = Dot11()
        dot.to_ds = True
        eq_(dot.to_ds, True)

    def test_from_ds(self):
        dot = Dot11()
        dot.from_ds = True
        eq_(dot.from_ds, True)

    def test_more_frag(self):
        dot = Dot11()
        dot.more_frag = 1
        eq_(dot.more_frag, True)

    def test_retry(self):
        dot = Dot11()
        dot.retry = 1
        eq_(dot.retry, True)

    def test_power_mgmt(self):
        dot = Dot11()
        dot.power_mgmt = 1
        eq_(dot.power_mgmt, True)

    def test_wep(self):
        dot = Dot11()
        dot.wep = 1
        eq_(dot.wep, True)

    def test_order(self):
        dot = Dot11()
        dot.order = 1
        eq_(dot.order, True)

    def test_duration_id(self):
        dot = Dot11()
        dot.duration_id = 0x7163
        eq_(dot.duration_id, 0x7163)

    def test_addr1(self):
        dot = Dot11()
        dot.addr1 = addr
        eq_(dot.addr1, addr)

    def test_add_tagged_option(self):
        dot = Dot11()
        dot.add_option(Dot11.OptionTypes.SSID, addr.to_bytes())
        opt = dot.search_option(Dot11.OptionTypes.SSID)
        ok_(len(opt) == 6)
        eq_(opt, addr.to_bytes())

    def test_serialize(self):
        pdu = Dot11.from_buffer(expected_packet)
        buf = pdu.serialize()
        eq_(expected_packet, buf)

