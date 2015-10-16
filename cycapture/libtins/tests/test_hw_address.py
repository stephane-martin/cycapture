# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import HWAddress

addr        = "00:de:ad:be:ef:00"
empty_addr  = "00:00:00:00:00:00"


class HWAddressTest(unittest.TestCase):
    def test_default(self):
        hwaddr1 = HWAddress()
        hwaddr2 = HWAddress(empty_addr)
        self.assertEquals(hwaddr1, hwaddr2)

    def test_short(self):
        self.assertEquals(HWAddress("33:34:35:00:00:00"), HWAddress("33:34:35"))

    def test_equals(self):
        self.assertEquals(HWAddress(addr), HWAddress(addr))

    def test_different(self):
        self.assertNotEquals(HWAddress(empty_addr), HWAddress(addr))

    def get_item(self):
        hwaddr = HWAddress("00:01:02:03:04:05")
        for i in range(6):
            self.assertEquals(hwaddr[i], i)

    def test_less_than(self):
        addr1 = HWAddress(addr)
        addr2 = HWAddress(empty_addr)
        bcast = HWAddress("ff:ff:ff:ff:ff:ff")
        self.assertLess(addr2, addr1)
        self.assertLess(addr2, bcast)

    def test_broadcast(self):
        self.assertFalse(HWAddress("ff:ff:ff:ff:ff:fe").is_broadcast())
        self.assertFalse(HWAddress("00:01:02:03:04:05").is_broadcast())
        self.assertTrue(HWAddress("ff:ff:ff:ff:ff:ff").is_broadcast())

    def test_unicast(self):
        self.assertFalse(HWAddress("ff:ff:ff:ff:ff:ff").is_unicast())
        self.assertFalse(HWAddress("03:02:03:04:05:06").is_unicast())
        self.assertTrue(HWAddress("de:ad:be:ef:00:00").is_unicast())

    def test_multicast(self):
        self.assertTrue(HWAddress("01:02:03:04:05:06").is_multicast())
        self.assertTrue(HWAddress("09:02:03:04:05:06").is_multicast())
        self.assertTrue(HWAddress("03:02:03:04:05:06").is_multicast())
        self.assertFalse(HWAddress("00:02:03:04:05:06").is_multicast())
        self.assertFalse(HWAddress("02:02:03:04:05:06").is_multicast())
