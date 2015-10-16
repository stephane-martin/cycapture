# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import IPv6Address

empty_addr = IPv6Address("::")


class IPv6AddressTest(unittest.TestCase):

    def test_default(self):
        self.assertEquals(IPv6Address(), empty_addr)

    def test_construct_from_string(self):
        addr = IPv6Address("2001:db8:85a3:8d3:1319:8a2e:370:7348")
        some_addr_str = "\x20\x01\x0d\xb8\x85\xa3\x08\xd3\x13\x19\x8a\x2e\x03\x70\x73\x48"
        self.assertEquals(addr, "2001:db8:85a3:8d3:1319:8a2e:370:7348")
        self.assertEquals(addr.to_buffer(), some_addr_str)

        addr = IPv6Address("2001:db8:85a3::1319:8a2e:370:7348")
        some_addr_str = "\x20\x01\x0d\xb8\x85\xa3\x00\x00\x13\x19\x8a\x2e\x03\x70\x73\x48"
        self.assertEquals(addr, "2001:db8:85a3::1319:8a2e:370:7348")
        self.assertEquals(addr.to_buffer(), some_addr_str)

        addr = IPv6Address("::1")
        self.assertEquals(addr.to_buffer(), "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")

    def test_str(self):
        l = [
            "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "2001:db8:85a3:8d3:1319:8a2e::",
            "1:db8:85a3:8d3:1319:8a2e:370:7348",
            "::85a3:8d3:1319:8a2e:370:7348",
            "::1:2:3"
        ]
        for s in l:
            self.assertEquals(s, str(IPv6Address(s)))

    def test_equals(self):
        self.assertEquals(IPv6Address("::1"), IPv6Address("::1"))
        self.assertEquals(IPv6Address("1::"), IPv6Address("1::"))
        self.assertEquals(IPv6Address("17f8::1"), IPv6Address("17f8:0::0:1"))

    def test_different(self):
        self.assertNotEquals(IPv6Address("17f8::12"), IPv6Address("17f8:0::1:12"))
        self.assertNotEquals(IPv6Address("::1"), IPv6Address("::2"))
        self.assertNotEquals(IPv6Address("4::"), IPv6Address("5::"))

    def test_less_than(self):
        self.assertLess(IPv6Address("17f8::1"), IPv6Address("17f8:0::0:5"))
        self.assertLess(IPv6Address("::1"), IPv6Address("::5"))
        self.assertLess(IPv6Address("1::"), IPv6Address("2::"))

    def test_loopback(self):
        self.assertTrue(IPv6Address("::1").is_loopback())
        self.assertFalse(IPv6Address("::2").is_loopback())
        self.assertFalse(IPv6Address("ffff::2").is_loopback())

    def test_multicast(self):
        self.assertTrue(IPv6Address("ff00::1").is_multicast())
        self.assertTrue(IPv6Address("ff02::1").is_multicast())
        self.assertTrue(IPv6Address("ffff::ffff").is_multicast())
        self.assertFalse(IPv6Address("f000::").is_multicast())
        self.assertFalse(IPv6Address("feaa::dead").is_multicast())

