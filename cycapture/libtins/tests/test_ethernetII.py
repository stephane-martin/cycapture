# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound
# from ..tins import IPv6

expected_packet = [
    170, 187, 204, 221, 238, 255, 138, 139, 140, 141, 142, 143, 208, 171,
    00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
    00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
    00, 00, 00, 00, 00, 00, 00, 00, 00, 00
]
expected_packet = "".join(chr(i) for i in expected_packet)

ip_packet = [
    255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 20,
    0, 1, 0, 0, 64, 0, 124, 231, 127, 0, 0, 1, 127, 0, 0, 1
]
ip_packet = "".join(chr(i) for i in ip_packet)

ipv6_packet = [
    255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 134, 221, 96, 0, 0,
    0, 0, 0, 59, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
]
ipv6_packet = "".join(chr(i) for i in ipv6_packet)

smallip_packet = [
    64, 97, 134, 43, 174, 3, 0, 36, 1, 254, 210, 68, 8, 0, 69, 0, 0, 40,
    53, 163, 64, 0, 127, 6, 44, 53, 192, 168, 1, 120, 173, 194, 42, 21,
    163, 42, 1, 187, 162, 113, 212, 162, 132, 15, 66, 219, 80, 16, 16,
    194, 34, 54, 0, 0, 0, 0, 0, 0, 0, 0
]
smallip_packet = "".join(chr(i) for i in smallip_packet)

src_addr = HWAddress("8a:8b:8c:8d:8e:8f")
dst_addr = HWAddress("aa:bb:cc:dd:ee:ff")
empty_addr = HWAddress()
p_type = 0xd0ab

def eth_equals(testcase, eth1, eth2):
    testcase.assertEquals(eth1.dst_addr, eth2.dst_addr)
    testcase.assertEquals(eth1.src_addr, eth2.src_addr)
    testcase.assertEquals(eth1.payload_type, eth2.payload_type)
    testcase.assertEquals(eth1.ref_inner_pdu() is None, eth2.ref_inner_pdu() is None)

class EthernetIITest(unittest.TestCase):

    def test_default_constructor(self):
        eth = EthernetII()
        self.assertEquals(eth.dst_addr, empty_addr)
        self.assertEquals(eth.src_addr, empty_addr)
        self.assertEquals(eth.payload_type, 0)
        self.assertIsNone(eth.ref_inner_pdu())
        self.assertEquals(eth.get_pdu_type(), PDU.ETHERNETII)

    def test_copy(self):
        eth = EthernetII.from_buffer(expected_packet)
        eth2 = eth.copy()
        eth_equals(self, eth, eth2)

    def test_nested(self):
        nested = EthernetII.from_buffer(expected_packet)
        eth1 = EthernetII.from_buffer(expected_packet)
        eth1.set_inner_pdu(nested)
        eth2 = eth1.copy()
        eth_equals(self, eth1, eth2)

    def test_src_addr(self):
        eth = EthernetII()
        eth.src_addr = src_addr
        self.assertEquals(eth.src_addr, src_addr)

    def test_dest_addr(self):
        eth = EthernetII()
        eth.dst_addr = dst_addr
        self.assertEquals(eth.dst_addr, dst_addr)

    def test_payload_type(self):
        eth = EthernetII()
        eth.payload_type = p_type
        self.assertEquals(eth.payload_type, p_type)

    def test_complete_constructor(self):
        eth = EthernetII(dest=dst_addr, src=src_addr) / EthernetII()
        self.assertEquals(eth.dst_addr, dst_addr)
        self.assertEquals(eth.src_addr, src_addr)
        self.assertEquals(eth.payload_type, 0)

    def test_serialize(self):
        eth = EthernetII.from_buffer(smallip_packet)
        self.assertTrue(eth.ref_inner_pdu() is not None)
        serialized = eth.serialize()
        self.assertEquals(len(serialized), len(smallip_packet))
        self.assertEquals(serialized, smallip_packet)

    def test_buffer_constructor(self):
        eth = EthernetII.from_buffer(expected_packet)
        self.assertEquals(eth.src_addr, src_addr)
        self.assertEquals(eth.dst_addr, dst_addr)
        self.assertEquals(eth.payload_type, p_type)

    def test_constructor_from_ip_buffer(self):
        eth = EthernetII.from_buffer(ip_packet)
        self.assertTrue(eth.ref_inner_pdu() is not None)
        self.assertEquals(eth.rfind_pdu(IP).serialize(), eth.ref_inner_pdu().serialize())

    #def test_constructor_from_ipv6_buffer(self):
    #    eth = EthernetII(buf=ipv6_packet)
    #    self.assertTrue(eth.ref_inner_pdu() is not None)
    #    self.assertEquals(eth.rfind_pdu(IPv6).serialize(), eth.ref_inner_pdu().serialize())


    def test_eliminate_ethernet_padding(self):
        eth = EthernetII.from_buffer(smallip_packet)
        self.assertTrue(eth.ref_inner_pdu() is not None)
        self.assertTrue(eth.rfind_pdu(IP) is not None)
        self.assertTrue(eth.rfind_pdu(TCP) is not None)
        self.assertRaises(PDUNotFound, eth.rfind_pdu, RAW)
