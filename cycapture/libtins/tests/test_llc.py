# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true

# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound, DNS, SNAP, LLC
# noinspection PyUnresolvedReferences
from .._tins import DNS_Query, DNS_Resource

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

from_buffer_info = _f([254, 72, 60, 59])
from_buffer_super = _f([75, 25, 5, 58])
from_buffer_unnumbered = _f([170, 23, 207])



class LLCTest(unittest.TestCase):
    def test_default_constr(self):
        llc = LLC()
        eq_(llc.ssap, 0)
        eq_(llc.dsap, 0)
        eq_(llc.type, LLC.Format.INFORMATION)
        eq_(llc.header_size, 4)
        eq_(llc.pdu_type, PDU.LLC)

    def test_params_constr(self):
        llc = LLC(0xAD, 0x16)
        eq_(llc.dsap, 0xAD)
        eq_(llc.ssap, 0x16)
        eq_(llc.type, LLC.Format.INFORMATION)
        eq_(llc.header_size, 4)
        eq_(llc.pdu_type, PDU.LLC)

    def test_group(self):
        llc = LLC()
        llc.group = 1
        assert_true(llc.group)
        llc.group = False
        assert_false(llc.group)

    def test_dsap(self):
        llc = LLC()
        llc.dsap = 0xaa
        eq_(llc.dsap, 0xaa)
        llc.dsap = 0x01
        eq_(llc.dsap, 0x01)

    def test_response(self):
        llc = LLC()
        llc.response = 1
        assert_true(llc.response)
        llc.response = False
        assert_false(llc.response)

    def test_ssap(self):
        llc = LLC()
        llc.ssap = 0xaa
        eq_(llc.ssap, 0xaa)
        llc.ssap = 0x01
        eq_(llc.ssap, 0x01)

    def test_type(self):
        llc = LLC()
        llc.type = LLC.Format.INFORMATION
        eq_(llc.type, LLC.Format.INFORMATION)
        llc.type = LLC.Format.SUPERVISORY
        eq_(llc.type, LLC.Format.SUPERVISORY)
        llc.type = LLC.Format.UNNUMBERED
        eq_(llc.type, LLC.Format.UNNUMBERED)

    def test_headsize(self):
        llc = LLC()
        llc.type = LLC.Format.INFORMATION
        eq_(llc.header_size, 4)
        llc.type = LLC.Format.SUPERVISORY
        eq_(llc.header_size, 4)
        llc.type = LLC.Format.UNNUMBERED
        eq_(llc.header_size, 3)

    def test_send_seq_number(self):
        llc = LLC()
        llc.type = LLC.Format.INFORMATION
        llc.send_seq_number = 18
        eq_(llc.send_seq_number, 18)
        llc.send_seq_number = 127
        eq_(llc.send_seq_number, 127)
        llc.type = LLC.Format.SUPERVISORY
        eq_(llc.send_seq_number, 0)
        llc.type = LLC.Format.UNNUMBERED
        eq_(llc.send_seq_number, 0)

    def test_receive_seq_number(self):
        llc = LLC()
        llc.type = LLC.Format.INFORMATION
        llc.receive_seq_number = 18
        eq_(llc.receive_seq_number, 18)
        llc.receive_seq_number = 127
        eq_(llc.receive_seq_number, 127)
        llc.type = LLC.Format.SUPERVISORY
        llc.receive_seq_number = 19
        eq_(llc.receive_seq_number, 19)
        llc.receive_seq_number = 127
        eq_(llc.receive_seq_number, 127)
        llc.type = LLC.Format.UNNUMBERED
        eq_(llc.receive_seq_number, 0)

    def test_poll_final(self):
        llc = LLC()
        llc.type = LLC.Format.INFORMATION
        llc.poll_final = True
        assert_true(llc.poll_final)
        llc.poll_final = 0
        assert_false(llc.poll_final)
        llc.type = LLC.Format.SUPERVISORY
        llc.poll_final = 1
        assert_true(llc.poll_final)
        llc.poll_final = 0
        assert_false(llc.poll_final)
        llc.type = LLC.Format.UNNUMBERED
        llc.poll_final = 1
        assert_true(llc.poll_final)
        llc.poll_final = 0
        assert_false(llc.poll_final)

    def test_supervisory_function(self):
        llc = LLC()
        llc.type = LLC.Format.INFORMATION
        eq_(llc.supervisory_function, 0)
        llc.type = LLC.Format.SUPERVISORY
        llc.supervisory_function = LLC.SupervisoryFunctions.RECEIVE_NOT_READY
        eq_(llc.supervisory_function, LLC.SupervisoryFunctions.RECEIVE_NOT_READY)
        llc.supervisory_function = LLC.SupervisoryFunctions.RECEIVE_READY
        eq_(llc.supervisory_function, LLC.SupervisoryFunctions.RECEIVE_READY)
        llc.type = LLC.Format.UNNUMBERED
        eq_(llc.supervisory_function, 0)

    def test_modifier_function(self):
        llc = LLC()
        llc.type = LLC.Format.INFORMATION
        eq_(llc.modifier_function, 0)
        llc.type = LLC.Format.SUPERVISORY
        eq_(llc.modifier_function, 0)
        llc.type = LLC.Format.UNNUMBERED
        llc.modifier_function = LLC.ModifierFunctions.TEST
        eq_(llc.modifier_function, LLC.ModifierFunctions.TEST)
        llc.modifier_function = LLC.ModifierFunctions.XID
        eq_(llc.modifier_function, LLC.ModifierFunctions.XID)

    def test_constr_buf(self):
        llc = LLC.from_buffer(from_buffer_info)
        eq_(llc.type, LLC.Format.INFORMATION)
        eq_(llc.header_size, 4)
        eq_(llc.dsap, 0xFE)
        eq_(llc.ssap, 0x48)
        assert_false(llc.group)
        assert_false(llc.response)
        assert_true(llc.poll_final)
        eq_(llc.send_seq_number, 30)
        eq_(llc.receive_seq_number, 29)

        llc_super = LLC.from_buffer(from_buffer_super)
        eq_(llc_super.header_size, 4)
        eq_(llc_super.dsap, 0x4B)
        eq_(llc_super.ssap, 0x19)
        assert_true(llc_super.group)
        assert_true(llc_super.response)
        assert_false(llc_super.poll_final)
        eq_(llc_super.receive_seq_number, 29)
        eq_(llc_super.supervisory_function, LLC.SupervisoryFunctions.RECEIVE_NOT_READY)

        llc_unnum = LLC.from_buffer(from_buffer_unnumbered)
        eq_(llc_unnum.header_size, 3)
        eq_(llc_unnum.dsap, 0xaa)
        eq_(llc_unnum.ssap, 0x17)
        assert_false(llc_unnum.group)
        assert_true(llc_unnum.response)
        assert_false(llc_unnum.poll_final)
        eq_(llc_unnum.modifier_function, LLC.ModifierFunctions.SABME)
