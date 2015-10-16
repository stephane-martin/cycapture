# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import IPv4Address, IPv4Range, IPv6Range, HWRange, HWAddress, IPv6Address

class AddressRangeTest(unittest.TestCase):

    def test_contains(self):
        def subtest1(r):
            self.assertTrue("192.168.0.0" in r)
            self.assertTrue("192.168.0.1" in r)
            self.assertTrue("192.168.0.254" in r)
            self.assertTrue("192.168.0.255" in r)
            self.assertTrue("192.168.0.123" in r)
            self.assertFalse("192.168.1.1" in r)

        def subtest2(r):
            self.assertTrue("192.168.254.192" in r)
            self.assertTrue("192.168.254.255" in r)
            self.assertFalse("192.168.254.0" in r)
            self.assertFalse("192.168.254.191" in r)

        def subtest3(r):
            self.assertTrue("dead::1" in r)
            self.assertTrue("dead::1fee" in r)
            self.assertTrue("dead::ffee" in r)
            self.assertFalse("dead::1:1" in r)
            self.assertFalse("dead::2:0" in r)

        subtest1(IPv4Range("192.168.0.0", "192.168.0.255"))
        subtest1(IPv4Range("192.168.0.0", mask="255.255.255.0"))
        subtest2(IPv4Range("192.168.254.192", "192.168.254.255"))
        subtest2(IPv4Range("192.168.254.192", mask="255.255.255.192"))
        subtest3(IPv6Range("dead::0", "dead::ffff"))
        subtest3(IPv6Range("dead::0", mask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:0"))

        r = HWRange("00:00:00:00:00:00", "00:00:00:00:00:ff")
        self.assertTrue("00:00:00:00:00:00" in r)
        self.assertTrue("00:00:00:00:00:10" in r)
        self.assertTrue("00:00:00:00:00:ff" in r)
        self.assertFalse("00:00:00:00:01:00" in r)

        r = HWAddress("00:00:00:00:00:00") / 40
        self.assertTrue("00:00:00:00:00:00" in r)
        self.assertTrue("00:00:00:00:00:10" in r)
        self.assertTrue("00:00:00:00:00:ff" in r)
        self.assertFalse("00:00:00:00:01:00" in r)

        r = HWAddress("00:00:00:00:00:00") / 38
        self.assertTrue("00:00:00:00:00:00" in r)
        self.assertTrue("00:00:00:00:02:00" in r)
        self.assertTrue("00:00:00:00:03:ff" in r)
        self.assertFalse("00:00:00:00:04:00" in r)


    def test_address_range(self):
        l = [str(addr) for addr in IPv4Range("192.168.0.0", mask="255.255.255.252")]
        self.assertEquals(l, ["192.168.0.1", "192.168.0.2"])

        l = [str(addr) for addr in IPv4Range("255.255.255.252", mask="255.255.255.252")]
        self.assertEquals(l, ["255.255.255.253", "255.255.255.254"])

        l = [str(addr) for addr in IPv6Range("dead::0", mask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc")]
        self.assertEquals(l, ["dead::1", "dead::2"])

        l = [str(addr) for addr in IPv6Range("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc", mask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc")]
        self.assertEquals(l, ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"])

        r1 = {str(addr) for addr in IPv4Range("192.168.0.0", mask="255.255.255.252")}
        r2 = {str(addr) for addr in IPv4Address("192.168.0.0") / 30}
        self.assertEquals(r1, r2)

        r1 = {str(addr) for addr in IPv4Range("255.255.255.252", mask="255.255.255.252")}
        r2 = {str(addr) for addr in IPv4Address("255.255.255.252") / 30}
        self.assertEquals(r1, r2)

        r1 = {str(addr) for addr in IPv6Range("dead::0", mask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc")}
        r2 = {str(addr) for addr in IPv6Address("dead::0") / 126}
        self.assertEquals(r1, r2)

        r1 = {str(addr) for addr in IPv6Range("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc", mask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc")}
        r2 = {str(addr) for addr in IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc") / 126}
        self.assertEquals(r1, r2)
