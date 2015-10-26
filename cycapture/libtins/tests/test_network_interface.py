# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound
# noinspection PyUnresolvedReferences
from .._tins import InvalidInterface, NetworkInterface, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"
IS_LINUX = platform.system().lower().strip() == "linux"

class NetworkInterfaceTest(unittest.TestCase):
    def test_constr_throw(self):
        self.assertRaises(InvalidInterface, NetworkInterface, "ishallnotexist")

    def test_constr_ip(self):
        addr = IPv4Address('127.0.0.1')
        iface = NetworkInterface(address=addr)
        if IS_LINUX:
            self.assertEquals(iface.name, "lo")
        if IS_MACOSX:
            self.assertEquals(iface.name, "lo0")

    def test_id(self):
        addr = IPv4Address('127.0.0.1')
        iface = NetworkInterface(address=addr)
        self.assertNotEquals(iface.id, 0)

    def test_info(self):
        addr = IPv4Address('127.0.0.1')
        iface = NetworkInterface(address=addr)
        addrs = iface.addresses()
        self.assertEquals(addrs['ip_addr'], "127.0.0.1")
        self.assertEquals(addrs['netmask'], "255.0.0.0")

    def test_equals(self):
        addr = IPv4Address('127.0.0.1')
        iface1 = NetworkInterface(address=addr)
        iface2 = NetworkInterface(address=addr)
        self.assertEquals(iface1, iface2)
        self.assertNotEquals(NetworkInterface(), iface1)
