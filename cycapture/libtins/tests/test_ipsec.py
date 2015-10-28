# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, IPSecAH, IPSecESP, OptionNotFound, DNS, DHCP, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

whole_packet = _f([
    194, 1, 87, 117, 0, 0, 194, 0, 87, 117, 0, 0, 8, 0, 69, 0, 0, 180,
    0, 107, 0, 0, 255, 51, 166, 169, 10, 0, 0, 1, 10, 0, 0, 2, 50, 4, 0,
    0, 129, 121, 183, 5, 0, 0, 0, 1, 39, 207, 192, 165, 228, 61, 105,
    179, 114, 142, 197, 176, 72, 218, 194, 228, 0, 0, 0, 1, 7, 65, 190,
    127, 138, 222, 64, 192, 43, 216, 26, 238, 15, 80, 111, 44, 70, 220,
    189, 73, 172, 173, 48, 187, 90, 9, 112, 128, 195, 214, 136, 212,
    155, 95, 34, 92, 232, 113, 132, 209, 249, 248, 173, 98, 103, 250,
    26, 162, 24, 151, 15, 209, 53, 182, 153, 55, 36, 84, 68, 95, 107,
    211, 204, 25, 177, 95, 183, 1, 178, 52, 217, 74, 7, 236, 107, 252,
    45, 61, 19, 53, 179, 1, 53, 102, 180, 116, 215, 195, 37, 155, 127,
    228, 185, 34, 165, 191, 163, 208, 144, 200, 154, 155, 109, 106, 183,
    242, 186, 17, 255, 199, 163, 135, 182, 5, 88, 122, 36, 168, 41, 156,
    125, 137, 194, 33, 153, 161, 189, 0
])

ah_expected_packet = _f([
    50, 4, 0, 0, 129, 121, 183, 5, 0, 0, 0, 1, 39, 207, 192, 165, 228,
    61, 105, 179, 114, 142, 197, 176, 72, 218, 194, 228, 0, 0, 0, 1, 7,
    65, 190, 127, 138, 222, 64, 192, 43, 216, 26, 238, 15, 80, 111, 44,
    70, 220, 189, 73, 172, 173, 48, 187, 90, 9, 112, 128, 195, 214, 136,
    212, 155, 95, 34, 92, 232, 113, 132, 209, 249, 248, 173, 98, 103,
    250, 26, 162, 24, 151, 15, 209, 53, 182, 153, 55, 36, 84, 68, 95,
    107, 211, 204, 25, 177, 95, 183, 1, 178, 52, 217, 74, 7, 236, 107,
    252, 45, 61, 19, 53, 179, 1, 53, 102, 180, 116, 215, 195, 37, 155,
    127, 228, 185, 34, 165, 191, 163, 208, 144, 200, 154, 155, 109, 106,
    183, 242, 186, 17, 255, 199, 163, 135, 182, 5, 88, 122, 36, 168, 41,
    156, 125, 137, 194, 33, 153, 161, 189, 0
])

esp_expected_packet = _f([
    72, 218, 194, 228, 0, 0, 0, 1, 7, 65, 190, 127, 138, 222, 64, 192,
    43, 216, 26, 238, 15, 80, 111, 44, 70, 220, 189, 73, 172, 173, 48,
    187, 90, 9, 112, 128, 195, 214, 136, 212, 155, 95, 34, 92, 232, 113,
    132, 209, 249, 248, 173, 98, 103, 250, 26, 162, 24, 151, 15, 209,
    53, 182, 153, 55, 36, 84, 68, 95, 107, 211, 204, 25, 177, 95, 183,
    1, 178, 52, 217, 74, 7, 236, 107, 252, 45, 61, 19, 53, 179, 1, 53,
    102, 180, 116, 215, 195, 37, 155, 127, 228, 185, 34, 165, 191, 163,
    208, 144, 200, 154, 155, 109, 106, 183, 242, 186, 17, 255, 199, 163,
    135, 182, 5, 88, 122, 36, 168, 41, 156, 125, 137, 194, 33, 153, 161,
    189, 0
])


class IPSEC_AH_Test(unittest.TestCase):
    def test_default_constr(self):
        ipsec = IPSecAH()
        eq_(ipsec.next_header, 0)
        eq_(ipsec.length, 2)
        eq_(ipsec.spi, 0)
        eq_(ipsec.seq_number, 0)
        eq_(len(ipsec.icv), 4)

    def test_eth_packet(self):
        eth = EthernetII.from_buffer(whole_packet)
        ok_(eth.rfind_pdu(IPSecAH) is not None)
        ok_(eth.rfind_pdu(IPSecESP) is not None)
        ok_(eth.rfind_pdu(RAW) is not None)

    def test_constr_buf(self):
        ipsec = IPSecAH.from_buffer(ah_expected_packet)
        icv = "\x27\xcf\xc0\xa5\xe4\x3d\x69\xb3\x72\x8e\xc5\xb0"
        eq_(ipsec.next_header, 0x32)
        eq_(ipsec.length, 4)
        eq_(ipsec.spi, 0x8179b705)
        eq_(ipsec.seq_number, 1)
        eq_(len(ipsec.icv), 12)
        eq_(ipsec.icv, icv)
        ok_(ipsec.rfind_pdu(IPSecESP) is not None)
        ok_(ipsec.rfind_pdu(RAW) is not None)

    def test_serialize(self):
        ipsec = IPSecAH.from_buffer(ah_expected_packet)
        eq_(ah_expected_packet, ipsec.serialize())

    def test_next_header(self):
        ipsec = IPSecAH()
        ipsec.next_header = 0x73
        eq_(ipsec.next_header, 0x73)

    def test_length(self):
        ipsec = IPSecAH()
        ipsec.length = 0x73
        eq_(ipsec.length, 0x73)

    def test_spi(self):
        ipsec = IPSecAH()
        ipsec.spi = 0x73a625fa
        eq_(ipsec.spi, 0x73a625fa)

    def test_seq_number(self):
        ipsec = IPSecAH()
        ipsec.seq_number = 0x73a625fa
        eq_(ipsec.seq_number, 0x73a625fa)

    def test_icv(self):
        ipsec = IPSecAH()
        ipsec.icv = "\x29\x52\x9a\x73"
        eq_(ipsec.icv, "\x29\x52\x9a\x73")


class IPSEC_ESP_Test(unittest.TestCase):
    def test_default_constr(self):
        ipsec = IPSecESP()
        eq_(ipsec.spi, 0)
        eq_(ipsec.seq_number, 0)

    def test_constr_buf(self):
        ipsec = IPSecESP.from_buffer(esp_expected_packet)
        eq_(ipsec.spi, 0x48dac2e4)
        eq_(ipsec.seq_number, 1)
        ok_(ipsec.rfind_pdu(RAW) is not None)

    def test_spi(self):
        ipsec = IPSecESP()
        ipsec.spi = 0x73a625fa
        eq_(ipsec.spi, 0x73a625fa)

    def test_seq_number(self):
        ipsec = IPSecESP()
        ipsec.seq_number = 0x73a625fa
        eq_(ipsec.seq_number, 0x73a625fa)

    def test_serialize(self):
        ipsec = IPSecESP.from_buffer(esp_expected_packet)
        eq_(esp_expected_packet, ipsec.serialize())


