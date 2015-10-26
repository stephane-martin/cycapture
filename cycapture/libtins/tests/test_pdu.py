# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, IPv4Address, ARP, PPI, Dot11Data

class PDUTest(unittest.TestCase):
    def test_find_pdu(self):
        ip = IP("192.168.0.1") / TCP(22, 52) / RAW("Test")
        ip.rfind_pdu(TCP)
        ip.rfind_pdu(RAW)
        assert_raises(PDUNotFound, ip.rfind_pdu, UDP)

    def test_concat(self):
        raw_payload = "Test"
        ip = IP("192.168.0.1") / TCP(22, 52) / RAW(raw_payload)
        eq_(ip.dst_addr, "192.168.0.1")
        assert_true(ip.ref_inner_pdu() is not None)
        tcp = ip.rfind_pdu(TCP)
        eq_(tcp.dport, 22)
        eq_(tcp.sport, 52)
        assert_true(tcp.ref_inner_pdu() is not None)
        raw = tcp.rfind_pdu(RAW)
        eq_(raw.payload_size, len(raw_payload))
        eq_(raw.payload, raw_payload)

    def test_concat2(self):
        raw_payload = "Test"
        ip = IP("192.168.0.1") / TCP(22, 52)
        tcp = ip.rfind_pdu(TCP)
        tcp /= RAW(raw_payload)
        raw = ip.rfind_pdu(RAW)
        eq_(raw.payload_size, len(raw_payload))
        eq_(raw.payload, raw_payload)

