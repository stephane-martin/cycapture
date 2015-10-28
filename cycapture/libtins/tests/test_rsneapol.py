# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, SNAP, UDP, ICMP, RSNEAPOL, DNS, DHCP, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

empty_iv = RSNEAPOL.key_iv_size * "\x00"

nonce = _f([
    185, 111, 231, 250, 202, 91, 39, 226, 77, 4, 241, 230, 108, 6, 225,
    155, 179, 58, 107, 36, 180, 57, 187, 228, 222, 217, 10, 204, 209, 51,
    30, 158
])

mic = _f([
    177, 186, 172, 85, 150, 74, 189, 48, 86, 133, 101, 42, 178, 38, 117,
    130
])

key = _f([
    226, 197, 79, 71, 243, 14, 201, 47, 66, 216, 213, 30, 49, 157, 245,
    72, 96, 109, 78, 227, 217, 132, 211, 67, 90, 21, 252, 88, 15, 62, 116,
    96, 64, 145, 16, 96, 239, 177, 67, 248, 253, 182, 10, 54, 203, 164,
    68, 152, 38, 7, 26, 255, 139, 147, 211, 46
])

rsc = _f([
    177, 6, 0, 0, 0, 0, 0, 0
])

tid = RSNEAPOL.id_size * "\x00"

expected_packet = _f([
    1, 3, 0, 151, 2, 19, 202, 0, 16, 0, 0, 0, 0, 0, 0, 0, 2, 185, 111,
    231, 250, 202, 91, 39, 226, 77, 4, 241, 230, 108, 6, 225, 155, 179,
    58, 107, 36, 180, 57, 187, 228, 222, 217, 10, 204, 209, 51, 30, 158,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 177, 6, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 177, 186, 172, 85, 150, 74, 189, 48,
    86, 133, 101, 42, 178, 38, 117, 130, 0, 56, 226, 197, 79, 71, 243,
    14, 201, 47, 66, 216, 213, 30, 49, 157, 245, 72, 96, 109, 78, 227,
    217, 132, 211, 67, 90, 21, 252, 88, 15, 62, 116, 96, 64, 145, 16, 96,
    239, 177, 67, 248, 253, 182, 10, 54, 203, 164, 68, 152, 38, 7, 26,
    255, 139, 147, 211, 46
])

eapol_over_snap = _f([
    170, 170, 3, 0, 0, 0, 136, 142, 2, 3, 0, 95, 2, 0, 138, 0, 16, 0,
    0, 0, 0, 0, 0, 0, 1, 82, 43, 37, 89, 147, 67, 237, 161, 188, 102
    , 113, 206, 250, 93, 102, 154, 119, 17, 84, 225, 191, 146, 83,
    238, 40, 0, 226, 176, 19, 64, 109, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 216,
    123, 212, 159
])


class RSN_EAPOL_Tests(unittest.TestCase):
    def check_equals(self, eapol1, eapol2):
        eq_(eapol1.version, eapol2.version)
        eq_(eapol1.packet_type, eapol2.packet_type)
        eq_(eapol1.type, eapol2.type)
        eq_(eapol1.length, eapol2.length)
        eq_(eapol1.key_length, eapol2.key_length)
        eq_(eapol1.replay_counter, eapol2.replay_counter)
        eq_(eapol1.key_iv, eapol2.key_iv)
        eq_(eapol1.id, eapol2.id)
        eq_(eapol1.rsc, eapol2.rsc)
        eq_(eapol1.wpa_length, eapol2.wpa_length)
        eq_(eapol1.nonce, eapol2.nonce)
        eq_(eapol1.mic, eapol2.mic)
        eq_(eapol1.key, eapol2.key)

    def test_default_constr(self):
        empty_nonce = RSNEAPOL.nonce_size * '\x00'
        empty_rsc = RSNEAPOL.rsc_size * '\x00'
        empty_id = RSNEAPOL.id_size * '\x00'
        eapol = RSNEAPOL()

        eq_(eapol.version, 1)
        eq_(eapol.packet_type, 0x3)
        eq_(eapol.type, RSNEAPOL.Types.RSN)
        eq_(eapol.length, 0)
        eq_(eapol.key_length, 0)
        eq_(eapol.replay_counter, 0)
        eq_(eapol.key_iv, empty_iv)
        eq_(eapol.id, empty_id)
        eq_(eapol.rsc, empty_rsc)
        eq_(eapol.wpa_length, 0)
        eq_(eapol.nonce, empty_nonce)
        eq_(eapol.mic, empty_iv)
        eq_(eapol.key, b'')

    def test_eapol_over_snap(self):
        snap = SNAP.from_buffer(eapol_over_snap)
        assert_true(snap.rfind_pdu(RSNEAPOL) is not None)

    def test_constr_buf(self):
        eapol = RSNEAPOL.from_buffer(expected_packet)
        eq_(eapol.version, 1)
        eq_(eapol.packet_type, 3)
        eq_(eapol.length, 151)
        eq_(eapol.type, RSNEAPOL.Types.RSN)

        eq_(eapol.key_t, 1)
        eq_(eapol.key_index, 0)
        eq_(eapol.install, 1)
        eq_(eapol.key_ack, 1)
        eq_(eapol.key_mic, 1)
        eq_(eapol.secure, 1)
        eq_(eapol.error, 0)
        eq_(eapol.request, 0)
        eq_(eapol.encrypted, 1)

        eq_(eapol.key_length, 16)
        eq_(eapol.replay_counter, 2)
        eq_(eapol.nonce, nonce)
        eq_(eapol.key_iv, empty_iv)
        eq_(eapol.rsc, rsc)
        eq_(eapol.id, tid)
        eq_(eapol.mic, mic)
        eq_(eapol.wpa_length, 56)
        eq_(eapol.key, key)

    def test_serialize(self):
        eapol = RSNEAPOL.from_buffer(expected_packet)
        buf = eapol.serialize()
        eq_(expected_packet, buf)

    def test_constr(self):
        eapol = RSNEAPOL()
        eapol.version = 1
        eapol.packet_type = 3
        eapol.length = 151
        eapol.key_length = 16
        eapol.replay_counter = 2
        eapol.nonce = nonce
        eapol.key_iv = empty_iv
        eapol.rsc = rsc
        eapol.id = tid
        eapol.mic= mic
        eapol.key = key
        eapol.key_descriptor = 2
        eapol.key_t = 1
        eapol.install = 1
        eapol.key_ack = 1
        eapol.key_mic = 1
        eapol.secure = 1
        eapol.encrypted = 1

        buf = eapol.serialize()
        eapol2 = RSNEAPOL.from_buffer(buf)
        self.check_equals(eapol, eapol2)
        eq_(buf, expected_packet)

    def test_replay_counter(self):
        eapol = RSNEAPOL()
        eapol.replay_counter = 0x7af3d91a1fd3ab
        eq_(eapol.replay_counter, 0x7af3d91a1fd3ab)

    def test_wpa_length(self):
        eapol = RSNEAPOL()
        eapol.wpa_length = 0x9af1
        eq_(eapol.wpa_length, 0x9af1)

    def test_key_iv(self):
        eapol = RSNEAPOL()
        eapol.key_iv = empty_iv
        eq_(eapol.key_iv, empty_iv)

    def test_nonce(self):
        eapol = RSNEAPOL()
        eapol.nonce = nonce
        eq_(eapol.nonce, nonce)

    def test_key(self):
        eapol = RSNEAPOL()
        k = _f([1, 9, 2, 0x71, 0x87, 0xfa, 0xdf])
        eapol.key = k
        eq_(eapol.key, k)


