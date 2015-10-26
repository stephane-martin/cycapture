# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound, DNS, DHCP, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

dhcp_chaddr = "16:ab:54:12:fa:ca:56:7f:1b:65:11:fa:da:ab:19:18"

sname = "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xbb\x19\x18" \
        "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xcb\x19\x18" \
        "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xeb\x19\x18" \
        "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xfb\x19\x18"

dhcp_file = "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xbb\x19\x18" \
            "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xcb\x19\x18" \
            "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xeb\x19\x18" \
            "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xfb\x19\x18" \
            "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xbb\x19\x18" \
            "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xcb\x19\x18" \
            "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xeb\x19\x18" \
            "\x16\xab\x54\x12\xfa\xca\x56\x7f\x1b\x65\x11\xfa\xda\xfb\x19\x18"

addr = "192.168.8.1"

expected_packet = _f([
    1, 1, 6, 31, 63, 171, 35, 222, 159, 26, 0, 0, 192, 168, 0, 102, 243,
    22, 34, 98, 167, 32, 11, 154, 123, 43, 55, 254, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 130, 83, 99,
    54, 4, 192, 168, 4, 2, 1, 4, 255, 255, 32, 11, 53, 1, 4, 3, 8, 192,
    168, 0, 1, 127, 0, 0, 1, 6, 8, 192, 168, 0, 2, 127, 0, 0, 1
])

class DHCPTest(unittest.TestCase):
    def check_equals(self, dhcp1, dhcp2):
        eq_(dhcp1.opcode, dhcp2.opcode)
        eq_(dhcp1.htype, dhcp2.htype)
        eq_(dhcp1.hlen, dhcp2.hlen)
        eq_(dhcp1.hops, dhcp2.hops)
        eq_(dhcp1.xid, dhcp2.xid)
        eq_(dhcp1.padding, dhcp2.padding)
        eq_(dhcp1.ciaddr, dhcp2.ciaddr)
        eq_(dhcp1.yiaddr, dhcp2.yiaddr)
        eq_(dhcp1.siaddr, dhcp2.siaddr)
        eq_(dhcp1.giaddr, dhcp2.giaddr)
        eq_(dhcp1.chaddr, dhcp2.chaddr)
        eq_(dhcp1.sname, dhcp2.sname)
        eq_(dhcp1.file, dhcp2.file)
        opts1 = dhcp1.options()
        opts2 = dhcp2.options()
        eq_(len(opts1), len(opts2))
        eq_(opts1.keys(), opts2.keys())
        for key in opts1:
            eq_(opts1[key], opts2[key])

    def test_constr(self):
        dhcp = DHCP()
        assert_equal(dhcp.htype, 1)
        assert_equal(dhcp.hlen, 6)

    def test_copy(self):
        dhcp1 = DHCP.from_buffer(expected_packet)
        dhcp2 = dhcp1.copy()
        self.check_equals(dhcp1, dhcp2)

    def test_opcode(self):
        dhcp = DHCP()
        dhcp.opcode = 0x71
        eq_(dhcp.opcode, 0x71)

    def test_htype(self):
        dhcp = DHCP()
        dhcp.htype = 0x71
        eq_(dhcp.htype, 0x71)

    def test_hlen(self):
        dhcp = DHCP()
        dhcp.hlen = 0x71
        eq_(dhcp.hlen, 0x71)

    def test_hops(self):
        dhcp = DHCP()
        dhcp.hops = 0x71
        eq_(dhcp.hops, 0x71)

    def test_xid(self):
        dhcp = DHCP()
        dhcp.xid = 0x71bd167c
        eq_(dhcp.xid, 0x71bd167c)

    def test_srcs(self):
        dhcp = DHCP()
        dhcp.secs = 0x71
        eq_(dhcp.secs, 0x71)

    def test_padding(self):
        dhcp = DHCP()
        dhcp.padding = 0x71bd
        eq_(dhcp.padding, 0x71bd)

    def test_ciaddr(self):
        dhcp = DHCP()
        dhcp.ciaddr = addr
        eq_(dhcp.ciaddr, addr)

    def test_yiaddr(self):
        dhcp = DHCP()
        dhcp.yiaddr = addr
        eq_(dhcp.yiaddr, addr)

    def test_siaddr(self):
        dhcp = DHCP()
        dhcp.siaddr = addr
        eq_(dhcp.siaddr, addr)

    def test_giaddr(self):
        dhcp = DHCP()
        dhcp.giaddr = addr
        eq_(dhcp.giaddr, addr)

    def test_chaddr(self):
        dhcp = DHCP()
        dhcp.chaddr = dhcp_chaddr
        eq_(dhcp.chaddr, dhcp_chaddr)

        dhcp.chaddr = "31:33:70:00"
        eq_("31:33:70:00", dhcp.chaddr[:11])

    def test_sname(self):
        dhcp = DHCP()
        dhcp.sname = sname
        eq_(dhcp.sname, sname)

    def test_file(self):
        dhcp = DHCP()
        dhcp.file = dhcp_file
        eq_(dhcp.file, dhcp_file)

    def test_type_opt(self):
        dhcp = DHCP()
        dhcp.type = DHCP.Flags.REQUEST
        eq_(dhcp.type, DHCP.Flags.REQUEST)

    def test_server_id_opt(self):
        dhcp = DHCP()
        dhcp.server_identifier = "192.168.0.1"
        eq_(dhcp.server_identifier, "192.168.0.1")

    def test_lease(self):
        dhcp = DHCP()
        dhcp.lease_time = 0x34f1
        eq_(dhcp.lease_time, 0x34f1)

    def test_subnet_mask(self):
        dhcp = DHCP()
        dhcp.subnet_mask = "192.168.0.1"
        eq_(dhcp.subnet_mask, "192.168.0.1")

    def test_routers_option(self):
        dhcp = DHCP()
        routers = [IPv4Address("192.168.0.253"), IPv4Address("10.123.45.67")]
        dhcp.routers = routers
        eq_(dhcp.routers, routers)

    def test_dns_option(self):
        dhcp = DHCP()
        dns = [IPv4Address("192.168.0.253"), IPv4Address("10.123.45.67")]
        dhcp.domain_name_servers = dns
        eq_(dhcp.domain_name_servers, dns)

    def test_domain_name_opt(self):
        dhcp = DHCP()
        domain = "libtins.test.domain"
        dhcp.domain_name = domain
        eq_(dhcp.domain_name, domain)

    def test_hostname_opt(self):
        dhcp = DHCP()
        hostname = "libtins-hostname"
        dhcp.hostname = hostname
        eq_(dhcp.hostname, hostname)

    def test_broadcast_opt(self):
        dhcp = DHCP()
        dhcp.broadcast = "192.168.0.1"
        eq_(dhcp.broadcast, "192.168.0.1")

    def test_constr_buffer(self):
        dhcp1 = DHCP.from_buffer(expected_packet)
        expected_routers = [IPv4Address("192.168.0.1"), IPv4Address("127.0.0.1")]
        eq_(dhcp1.opcode, DHCP.Flags.DISCOVER)
        eq_(dhcp1.htype, 1)
        eq_(dhcp1.hlen, 6)
        eq_(dhcp1.hops, 0x1f)
        eq_(dhcp1.xid, 0x3fab23de)
        eq_(dhcp1.secs, 0x9f1a)
        eq_(dhcp1.padding, 0)
        eq_(dhcp1.ciaddr, "192.168.0.102")
        eq_(dhcp1.yiaddr, "243.22.34.98")
        eq_(dhcp1.giaddr, "123.43.55.254")
        eq_(dhcp1.siaddr, "167.32.11.154")
        eq_(dhcp1.server_identifier, "192.168.4.2")
        eq_(dhcp1.routers, expected_routers)

    def test_serialize(self):
        dhcp1 = DHCP.from_buffer(expected_packet)
        buf = dhcp1.serialize()
        eq_(expected_packet, buf)
        dhcp2 = DHCP.from_buffer(buf)
        self.check_equals(dhcp1, dhcp2)

