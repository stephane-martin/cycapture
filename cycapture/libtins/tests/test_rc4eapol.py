# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, EAPOL, PDU, IP, TCP, RAW, RC4EAPOL, UDP, ICMP, OptionNotFound, DNS, DHCP, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"


def _f(packet):
    return "".join(chr(i) for i in packet)


class RC4_EAPOL_Test(unittest.TestCase):
    def test_default_constr(self):
        eapol = RC4EAPOL()
        eq_(eapol.version, 1)
        eq_(eapol.packet_type, 0x3)
        eq_(eapol.type, EAPOL.Types.RC4)
        eq_(eapol.length, 0)
        eq_(eapol.key_length, 0)
        eq_(eapol.replay_counter, 0)
        eq_(eapol.key_iv, RC4EAPOL.key_iv_size * "\x00")
        eq_(eapol.key_flag, 0)
        eq_(eapol.key_index, 0)
        eq_(eapol.key_sign, RC4EAPOL.key_sign_size * "\x00")
        eq_(eapol.key, b'')

    def test_version(self):
        eapol = RC4EAPOL()
        eapol.version = 0x7a
        eq_(eapol.version, 0x7a)

    def test_packet_type(self):
        eapol = RC4EAPOL()
        eapol.packet_type = 0x7a
        eq_(eapol.packet_type, 0x7a)

    def test_length(self):
        eapol = RC4EAPOL()
        eapol.length = 0x7af2
        eq_(eapol.length, 0x7af2)

    def test_type(self):
        eapol = RC4EAPOL()
        eapol.type = 0x7a
        eq_(eapol.type, 0x7a)

    def test_keylength(self):
        eapol = RC4EAPOL()
        eapol.key_length = 0x7af3
        eq_(eapol.key_length, 0x7af3)

    def test_replay_counter(self):
        eapol = RC4EAPOL()
        eapol.replay_counter = 0x7af3d91a1fd3abL
        eq_(eapol.replay_counter, 0x7af3d91a1fd3abL)

    def test_key_iv(self):
        iv =_f(range(RC4EAPOL.key_iv_size))
        eapol = RC4EAPOL()
        eapol.key_iv = iv
        eq_(eapol.key_iv, iv)

    def test_key_flag(self):
        eapol = RC4EAPOL()
        eapol.key_flag = 1
        eq_(eapol.key_flag, 1)
        eapol.key_flag = 0
        eq_(eapol.key_flag, 0)

    def test_key_index(self):
        eapol = RC4EAPOL()
        eapol.key_index = 0x7d
        eq_(eapol.key_index, 0x7d)

    def test_key_sign(self):
        sign =_f(range(RC4EAPOL.key_sign_size))
        eapol = RC4EAPOL()
        eapol.key_sign = sign
        eq_(eapol.key_sign, sign)

    def test_key(self):
        eapol = RC4EAPOL()
        key = _f([1, 9, 2, 0x71, 0x87, 0xfa, 0xdf])
        eapol.key = key
        eq_(eapol.key, key)

