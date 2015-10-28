# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, Dot1Q, UDP, ICMP, OptionNotFound, ARP, DHCP, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

expected_packet = _f([
    255, 255, 255, 255, 255, 255, 0, 25, 6, 234, 184, 193, 129, 0, 176, 
    123, 8, 6, 0, 1, 8, 0, 6, 4, 0, 2, 0, 25, 6, 234, 184, 193, 192, 168, 
    123, 1, 255, 255, 255, 255, 255, 255, 192, 168, 123, 1, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
])



class Dot1Q_Test(unittest.TestCase):
    def test_default_constr(self):
        dot = Dot1Q()
        eq_(dot.payload_type, 0)
        eq_(dot.priority, 0)
        eq_(dot.cfi, 0)
        eq_(dot.id, 0)
    
    def test_constr_buf(self):
        eth = EthernetII.from_buffer(expected_packet)
        dot =  eth.rfind_pdu(Dot1Q)
        eq_(dot.payload_type, 0x806)
        eq_(dot.priority, 5)
        eq_(dot.cfi, 1)
        eq_(dot.id, 123)

        arp = dot.rfind_pdu(ARP)
        eq_(arp.sender_hw_addr, "00:19:06:ea:b8:c1")

    def test_serialize(self):
        eth = EthernetII.from_buffer(expected_packet)
        buf = eth.serialize()
        eq_(expected_packet, buf)

    def test_payload_type(self):
        dot = Dot1Q()
        dot.payload_type = 0x9283
        eq_(dot.payload_type, 0x9283)

    def test_priority(self):
        dot = Dot1Q()
        dot.priority = 5
        eq_(dot.priority, 5)

    def test_cfi(self):
        dot = Dot1Q()
        dot.cfi = 1
        eq_(dot.cfi, 1)

    def test_id(self):
        dot = Dot1Q()
        dot.id = 3543
        eq_(dot.id, 3543)
