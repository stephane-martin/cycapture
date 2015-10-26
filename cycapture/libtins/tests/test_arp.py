# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, IPv4Address, ARP

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"


def _f(packet):
    return "".join(chr(i) for i in packet)

empty_addr = HWAddress()
hw_addr1 = "13:da:de:f1:01:85"
hw_addr2 = "7a:1f:f4:39:ab:0d"
addr1 = 0x1234
addr2 = 0xa3f1
expected_packet = _f([
    0, 1, 8, 0, 6, 4, 0, 2, 3, 222, 245, 18, 9, 250, 192, 168, 45, 231,
    245, 18, 218, 103, 189, 13, 32, 155, 81, 254
])


class ARPTest(unittest.TestCase):
    def check_equals(self, arp1, arp2):
        eq_(arp1.opcode, arp2.opcode)
        eq_(arp1.hw_addr_length, arp2.hw_addr_length)
        eq_(arp1.hw_addr_format, arp2.hw_addr_format)
        eq_(arp1.prot_addr_length, arp2.prot_addr_length)
        eq_(arp1.prot_addr_format, arp2.prot_addr_format)
        eq_(arp1.sender_ip_addr, arp2.sender_ip_addr)
        eq_(arp1.target_ip_addr, arp2.target_ip_addr)
        eq_(arp1.sender_hw_addr, arp2.sender_hw_addr)
        eq_(arp1.target_hw_addr, arp2.target_hw_addr)
        eq_(arp1.ref_inner_pdu() is None, arp2.ref_inner_pdu() is None)

    def test_default_constr(self):
        arp = ARP()
        eq_(arp.target_ip_addr, IPv4Address())
        eq_(arp.sender_ip_addr, IPv4Address())
        eq_(arp.target_hw_addr, HWAddress())
        eq_(arp.sender_hw_addr, HWAddress())
        eq_(arp.pdu_type, PDU.ARP)

    def test_copy(self):
        arp1 = ARP(addr1, addr2, hw_addr1, hw_addr2)
        arp2 = arp1.copy()
        self.check_equals(arp1, arp2)

    def test_nested(self):
        nested_arp = ARP(addr1, addr2, hw_addr1, hw_addr2)
        arp1 = ARP(addr1, addr2, hw_addr1, hw_addr2)
        arp1.set_inner_pdu(nested_arp)
        arp2 = arp1.copy()
        self.check_equals(arp1, arp2)

    def test_complete_constr(self):
        arp = ARP(addr1, addr2, hw_addr1, hw_addr2)
        eq_(arp.target_hw_addr, hw_addr1)
        eq_(arp.sender_hw_addr, hw_addr2)
        eq_(arp.target_ip_addr, addr1)
        eq_(arp.sender_ip_addr, addr2)

    def test_sender_ip_addr(self):
        arp = ARP()
        arp.sender_ip_addr = addr1
        eq_(arp.sender_ip_addr, addr1)

    def test_targer_ip_addr(self):
        arp = ARP()
        arp.target_ip_addr = addr1
        eq_(arp.target_ip_addr, addr1)

    def test_target_hw_addr(self):
        arp = ARP()
        arp.target_hw_addr = hw_addr1
        eq_(arp.target_hw_addr, hw_addr1)

    def test_sender_hw_addr(self):
        arp = ARP()
        arp.sender_hw_addr = hw_addr1
        eq_(arp.sender_hw_addr, hw_addr1)

    def test_prot_addr_format(self):
        arp = ARP()
        arp.prot_addr_format = 0x45fa
        eq_(arp.prot_addr_format, 0x45fa)

    def test_prot_addr_length(self):
        arp = ARP()
        arp.prot_addr_length = 0x4f
        eq_(arp.prot_addr_length, 0x4f)

    def test_hw_addr_format(self):
        arp = ARP()
        arp.hw_addr_format = 0x45fa
        eq_(arp.hw_addr_format, 0x45fa)

    def test_hw_addr_length(self):
        arp = ARP()
        arp.hw_addr_length = 0xd1
        eq_(arp.hw_addr_length, 0xd1)

    def test_opcode(self):
        arp = ARP()
        arp.opcode = ARP.Flags.REQUEST
        eq_(arp.opcode, ARP.Flags.REQUEST)

    def test_serialize(self):
        arp1 = ARP("192.168.0.1", "192.168.0.100", hw_addr1, hw_addr2)
        buf1 = arp1.serialize()
        arp2 = arp1.copy()
        buf2 = arp2.serialize()
        eq_(buf1, buf2)

    def test_constr_buffer(self):
        arp1 = ARP.from_buffer(expected_packet)
        buf1 = arp1.serialize()
        arp2 = ARP.from_buffer(buf1)
        self.check_equals(arp1, arp2)
