# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true

# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, Dot3, DNS, SNAP, STP, LLC

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

expected_packet = _f([
    146, 131, 138, 146, 146, 128, 0, 0, 144, 76, 8, 23, 181, 0, 146, 131,
    120, 128, 0, 0, 144, 76, 8, 23, 181, 128, 1, 15, 0, 20, 0, 2, 0, 0,
    0
])

class STPTest(unittest.TestCase):
    def check_equals(self, bpdu1, bpdu2):
        eq_(bpdu1.priority, bpdu2.priority)
        eq_(bpdu1.ext_id, bpdu2.ext_id)
        eq_(bpdu1.id, bpdu2.id)

    def test_default_constr(self):
        stp = STP()
        eq_(stp.proto_id, 0)
        eq_(stp.proto_version, 0)
        eq_(stp.bpdu_type, 0)
        eq_(stp.bpdu_flags, 0)
        eq_(stp.root_path_cost, 0)
        eq_(stp.port_id, 0)
        eq_(stp.msg_age, 0)
        eq_(stp.max_age, 0)
        eq_(stp.hello_time, 0)
        eq_(stp.fwd_delay, 0)

    def test_constr_buf(self):
        stp = STP.from_buffer(expected_packet)
        bpdu = STP.bpdu_id_t(0x8, 0, "00:90:4c:08:17:b5")
        eq_(stp.proto_id, 0x9283)
        eq_(stp.proto_version, 0x8a)
        eq_(stp.bpdu_type, 0x92)
        eq_(stp.bpdu_flags, 0x92)
        self.check_equals(bpdu, stp.root_id)
        eq_(stp.root_path_cost, 0x928378)
        self.check_equals(bpdu, stp.bridge_id)
        eq_(stp.port_id, 0x8001)
        eq_(stp.msg_age, 15)
        eq_(stp.max_age, 20)
        eq_(stp.hello_time, 2)
        eq_(stp.fwd_delay, 0)

    def test_bpduid(self):
        expected = _f([
            0, 0, 0, 0, 0, 128, 100, 0, 28, 14, 135, 120, 0, 0, 0, 0, 4, 128,
            100, 0, 28, 14, 135, 133, 0, 128, 4, 1, 0, 20, 0, 2, 0, 15, 0, 0,
            0, 0, 0, 0, 0, 0, 0
        ])
        stp = STP.from_buffer(expected)
        bpdu = STP.bpdu_id_t(0x8, 100, "00:1c:0e:87:78:00")
        self.check_equals(bpdu, stp.root_id)

    def test_chained_pdus(self):
        input_s = _f([
            1, 128, 194, 0, 0, 0, 0, 144, 76, 8, 23, 181, 0, 38, 66, 66, 3,
            0, 0, 0, 0, 0, 128, 0, 0, 144, 76, 8, 23, 181, 0, 0, 0, 0, 128,
            0, 0, 144, 76, 8, 23, 181, 128, 1, 0, 0, 20, 0, 2, 0, 0, 0
        ])
        pkt = Dot3.from_buffer(input_s)
        stp = pkt.rfind_pdu(STP)
        assert_true(stp is not None)
        llc = pkt.rfind_pdu(LLC)
        assert_true(llc is not None)
        eq_(stp.port_id, 0x8001)
        eq_(stp.msg_age, 0)
        eq_(stp.max_age, 20)
        eq_(stp.hello_time, 2)
        llc.dsap = 0
        llc.ssap = 0
        eq_(input_s, pkt.serialize())

    def test_serialize(self):
        stp = STP.from_buffer(expected_packet)
        eq_(stp.serialize(), expected_packet)

    def test_protoid(self):
        stp = STP()
        stp.proto_id = 0x9283
        eq_(stp.proto_id, 0x9283)

    def test_proto_version(self):
        stp = STP()
        stp.proto_version = 0x15
        eq_(stp.proto_version, 0x15)

    def test_bpdutype(self):
        stp = STP()
        stp.bpdu_type = 0x15
        eq_(stp.bpdu_type, 0x15)

    def test_bpduflags(self):
        stp = STP()
        stp.bpdu_flags = 0x15
        eq_(stp.bpdu_flags, 0x15)

    def test_root_path_cost(self):
        stp = STP()
        stp.root_path_cost = 0x28378462
        eq_(stp.root_path_cost, 0x28378462)

    def test_port_id(self):
        stp = STP()
        stp.port_id = 0x9283
        eq_(stp.port_id, 0x9283)

    def test_msg_age(self):
        stp = STP()
        stp.msg_age = 15
        eq_(stp.msg_age, 15)

    def test_max_age(self):
        stp = STP()
        stp.max_age = 15
        eq_(stp.max_age, 15)

    def test_fwd_delay(self):
        stp = STP()
        stp.fwd_delay = 15
        eq_(stp.fwd_delay, 15)

    def test_hello_time(self):
        stp  = STP()
        stp.hello_time = 15
        eq_(stp.hello_time, 15)

    def test_root_id(self):
        stp = STP()
        bpdu = STP.bpdu_id_t(0x8, 100, "00:1c:0e:87:78:00")
        stp.root_id = bpdu
        self.check_equals(stp.root_id, bpdu)

    def test_bridge_id(self):
        stp = STP()
        bpdu = STP.bpdu_id_t(0x8, 100, "00:1c:0e:87:78:00")
        stp.bridge_id = bpdu
        self.check_equals(stp.bridge_id, bpdu)

