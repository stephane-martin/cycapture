# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import IPv4Address

ip_string = "192.168.0.225"

class IPv4AddressTest(unittest.TestCase):
    def test_constructor(self):
        addr1 = IPv4Address(ip_string)
        addr2 = IPv4Address(ip_string)
        self.assertEquals(str(addr1), ip_string)
        self.assertEquals(str(addr2), ip_string)
        self.assertNotEquals(addr1, "192.168.0.254")

    def test_convert_integer(self):
        addr1 = IPv4Address(ip_string)
        as_int = int(addr1)
        addr2 = IPv4Address(as_int)
        self.assertEquals(addr1, addr2)
        as_int2 = int(addr2)
        self.assertEquals(as_int, as_int2)

    def test_convert_string(self):
        addr1 = IPv4Address(ip_string)
        self.assertEquals(str(addr1), ip_string)

    def test_equality(self):
        addr1 = IPv4Address(ip_string)
        addr2 = IPv4Address(ip_string)
        self.assertEquals(addr1, addr2)
        self.assertNotEquals(addr1, "127.0.0.1")

    def test_less_than(self):
        addr1 = IPv4Address(ip_string)
        addr2 = IPv4Address(ip_string)
        self.assertFalse(addr1 < addr2)
        self.assertFalse(addr1 > addr2)
        self.assertLess(addr1, "192.168.1.2")
        self.assertLess(addr1, "192.168.0.226")
        self.assertLess(addr1, "193.0.0.0")
        self.assertGreater("193.0.0.0", addr1)

    def test_private(self):
        l = [
            (True, "192.168.0.1"), (True, "192.168.133.7"), (True, "192.168.255.254"), (False, "192.169.0.1"),
            (False, "192.167.255.254"), (True, "10.0.0.1"), (True, "10.5.1.2"), (True, "10.255.255.254"),
            (False, "11.0.0.1"), (False, "9.255.255.254"), (True, "172.16.0.1"), (True, "172.31.255.254"),
            (True, "172.20.13.75"), (False, "172.15.0.1"), (False, "172.32.0.1"), (False, "100.100.100.100"),
            (False, "199.199.29.10")
        ]
        for res, addr in l:
            self.assertEquals(IPv4Address(addr).is_private(), res)

    def test_multicast(self):
        self.assertTrue(IPv4Address("224.0.0.1").is_multicast())
        self.assertTrue(IPv4Address("226.3.54.132").is_multicast())
        self.assertTrue(IPv4Address("239.255.255.255").is_multicast())
        self.assertFalse(IPv4Address("223.255.255.255").is_multicast())
        self.assertFalse(IPv4Address("240.0.0.0").is_multicast())

    def test_broadcast(self):
        self.assertTrue(IPv4Address("255.255.255.255").is_broadcast())
        self.assertFalse(IPv4Address("226.3.54.132").is_broadcast())
        self.assertFalse(IPv4Address("127.0.0.1").is_broadcast())

    def test_unicast(self):
        self.assertFalse(IPv4Address("255.255.255.255").is_unicast())
        self.assertFalse(IPv4Address("224.0.0.1").is_unicast())
        self.assertTrue(IPv4Address("240.0.0.0").is_unicast())
        self.assertTrue(IPv4Address("127.0.0.1").is_unicast())

