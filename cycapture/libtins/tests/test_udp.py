# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"


def _f(packet):
    return "".join(chr(i) for i in packet)


expected_packet = _f([
    245, 26, 71, 241, 8, 0, 0, 0
])


checksum_packet = _f([
    69, 0, 0, 48, 35, 109, 64, 0, 64, 17, 25, 78, 0, 0, 0, 0, 127, 0, 0,
    1, 5, 57, 155, 11, 0, 28, 84, 167, 97, 115, 100, 97, 115, 100, 115,
    97, 115, 100, 97, 115, 100, 115, 97, 100, 97, 115, 100, 10
])


def check_equals(obj, udp1, udp2):
    obj.assertEquals(udp1.dport, udp2.dport)
    obj.assertEquals(udp1.sport, udp2.sport)
    obj.assertEquals(udp1.length, udp2.length)
    obj.assertEquals(udp1.size, udp2.size)
    obj.assertEquals(udp1.header_size, udp2.header_size)
    obj.assertEquals(udp1.ref_inner_pdu() is None, udp2.ref_inner_pdu() is None)


class UDPTest(unittest.TestCase):
    def test_default_constructor(self):
        udp = UDP()
        self.assertEquals(udp.dport, 0)
        self.assertEquals(udp.sport, 0)
        self.assertTrue(udp.ref_inner_pdu() is None)

    def test_checksum_check(self):
        pkt1 = IP.from_buffer(checksum_packet)
        udp1 = pkt1.rfind_pdu(UDP)
        checksum = udp1.checksum

        buf = pkt1.serialize()
        pkt2 = IP.from_buffer(buf)
        udp2 = pkt2.rfind_pdu(UDP)
        self.assertEquals(checksum, udp2.checksum)
        self.assertEquals(udp1.checksum, udp2.checksum)

    def test_copy_constructor(self):
        udp1 = UDP.from_buffer(expected_packet)
        udp2 = udp1.copy()
        check_equals(self, udp1, udp2)

    def test_complete_constr(self):
        udp = UDP(0x1234, 0x4321)
        self.assertEquals(udp.dport, 0x1234)
        self.assertEquals(udp.sport, 0x4321)

    def test_dport(self):
        udp = UDP()
        udp.dport = 0x1234
        self.assertEquals(udp.dport, 0x1234)

    def test_sport(self):
        udp = UDP()
        udp.sport = 0x1234
        self.assertEquals(udp.sport, 0x1234)

    def test_length(self):
        udp = UDP()
        udp.length = 0x1234
        self.assertEquals(udp.length, 0x1234)

    def test_type(self):
        udp = UDP()
        self.assertEquals(udp.pdu_type, PDU.UDP)

    def test_clone(self):
        udp1 = UDP()
        udp1.sport = 0x1234
        udp1.dport = 0x4321
        udp1.length = 0xdead
        udp2 = udp1.copy()

        self.assertEquals(udp2.sport, 0x1234)
        self.assertEquals(udp2.dport, 0x4321)
        self.assertEquals(udp2.length, 0xdead)
        self.assertEquals(udp2.pdu_type, PDU.UDP)

    def test_serialize(self):
        udp1 = UDP()
        udp1.sport = 0x1234
        udp1.dport = 0x4321
        udp1.length = 0xdead
        buf = udp1.serialize()
        udp2 = udp1.copy()
        buf2 = udp2.serialize()
        self.assertEquals(buf, buf2)

    def test_constr_from_buf(self):
        udp1 = UDP.from_buffer(expected_packet)
        buf = udp1.serialize()
        self.assertEquals(len(buf), len(expected_packet))
        self.assertEquals(udp1.dport, 0x47f1)
        self.assertEquals(udp1.sport, 0xf51a)
        self.assertEquals(udp1.length, 8)

        udp2 = UDP.from_buffer(buf)
        self.assertEquals(udp1.dport, udp2.dport)
        self.assertEquals(udp1.sport, udp2.sport)
        self.assertEquals(udp1.length, udp2.length)
        self.assertEquals(udp1.size, udp2.size)
        self.assertEquals(udp1.header_size, udp2.header_size)
