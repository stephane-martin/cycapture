# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"


def _f(packet):
    return "".join(chr(i) for i in packet)


def check_equals(obj, icmp1, icmp2):
    obj.assertEquals(icmp1.type, icmp2.type)
    obj.assertEquals(icmp1.code, icmp2.code)
    obj.assertEquals(icmp1.gateway, icmp2.gateway)
    obj.assertEquals(icmp1.id, icmp2.id)
    obj.assertEquals(icmp1.sequence, icmp2.sequence)
    obj.assertEquals(icmp1.pointer, icmp2.pointer)
    obj.assertEquals(icmp1.mtu, icmp2.mtu)
    obj.assertEquals(icmp1.ref_inner_pdu() is None, icmp2.ref_inner_pdu() is None)

expected1 = _f([8, 1, 173, 123, 86, 209, 243, 177])
expected2 = _f([12, 0, 116, 255, 127, 0, 0, 0])


expected_packet_count = 1

ts_request = _f([
    13, 0, 180, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 106, 97, 106, 97, 106
])

ts_reply = _f([
    14, 0, 172, 45, 0, 0, 0, 0, 0, 0, 0, 0, 4, 144, 30, 89, 4, 144, 30, 89, 0, 0, 0, 0, 0, 0
])

class ICMPTest(unittest.TestCase):
    def test_default_constr(self):
        icmp = ICMP()
        self.assertEquals(icmp.code, 0)
        self.assertEquals(icmp.type, ICMP.Flags.ECHO_REQUEST)
        self.assertEquals(icmp.id, 0)
        self.assertEquals(icmp.checksum, 0)

    def test_copy(self):
        icmp1 = ICMP.from_buffer(expected1)
        icmp2 = icmp1.copy()
        check_equals(self, icmp1, icmp2)

    def test_nested(self):
        nested = ICMP.from_buffer(expected1)
        icmp1 = ICMP.from_buffer(expected1)
        icmp1.set_inner_pdu(nested)
        icmp2 = icmp1.copy()
        check_equals(self, icmp1, icmp2)

    def test_flag(self):
        icmp = ICMP(ICMP.Flags.ECHO_REPLY)
        self.assertEquals(icmp.type, ICMP.Flags.ECHO_REPLY)

    def test_checksum_on_timestamp(self):
        raw_pkt = _f([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 45, 0, 1, 0,
            0, 128, 1, 185, 25, 192, 168, 0, 100, 192, 168, 0, 1, 13, 0, 237,
            141, 0, 0, 0, 0, 159, 134, 1, 0, 151, 134, 1, 0, 152, 134, 1, 0,
            98, 111, 105, 110, 103, 0
        ])

        pkt = EthernetII.from_buffer(raw_pkt)
        pkt.serialize()
        self.assertEquals(pkt.rfind_pdu(IP).checksum, 0xb919)
        self.assertEquals(pkt.rfind_pdu(ICMP).checksum, 0xed8d)

    def test_address_mask_request(self):
        raw_packet = _f([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 32, 0, 1, 0,
            0, 64, 1, 249, 38, 192, 168, 0, 100, 192, 168, 0, 1, 17, 0, 234,
            249, 0, 0, 0, 0, 1, 2, 3, 4
        ])
        pkt = EthernetII.from_buffer(raw_packet)
        buf = pkt.serialize()
        self.assertEquals(pkt.rfind_pdu(IP).checksum, 0xf926)
        self.assertEquals(pkt.rfind_pdu(ICMP).checksum, 0xeaf9)
        self.assertEquals(str(pkt.rfind_pdu(ICMP).address_mask), "1.2.3.4")

    def test_code(self):
        icmp = ICMP()
        icmp.code = 0x7a
        self.assertEquals(icmp.code, 0x7a)

    def test_id(self):
        icmp = ICMP()
        icmp.id = 0x7af1
        self.assertEquals(icmp.id, 0x7af1)

    def test_seq(self):
        icmp = ICMP()
        icmp.sequence = 0x7af1
        self.assertEquals(icmp.sequence, 0x7af1)

    def test_type(self):
        icmp = ICMP()
        icmp.type = ICMP.Flags.ECHO_REPLY
        self.assertEquals(icmp.type, ICMP.Flags.ECHO_REPLY)

    def test_gateway(self):
        icmp = ICMP()
        icmp.gateway = "1.2.3.4"
        self.assertEquals(str(icmp.gateway), "1.2.3.4")

    def test_mtu(self):
        icmp = ICMP()
        icmp.mtu = 0x7af1
        self.assertEquals(icmp.mtu, 0x7af1)

    def test_pointer(self):
        icmp = ICMP()
        icmp.pointer = 0xf1
        self.assertEquals(icmp.pointer, 0xf1)

    def test_original_timestamp(self):
        icmp = ICMP()
        icmp.original_timestamp = 0x1f8172da
        self.assertEquals(icmp.original_timestamp, 0x1f8172da)

    def test_receive_timestamp(self):
        icmp = ICMP()
        icmp.receive_timestamp = 0x1f8172da
        self.assertEquals(icmp.receive_timestamp, 0x1f8172da)

    def test_transmit_timestamp(self):
        icmp = ICMP()
        icmp.transmit_timestamp = 0x1f8172da
        self.assertEquals(icmp.transmit_timestamp, 0x1f8172da)

    def test_address_mask(self):
        icmp = ICMP()
        icmp.address_mask = "192.168.0.1"
        self.assertEquals(str(icmp.address_mask), "192.168.0.1")

    def test_set_echo_request(self):
        icmp = ICMP()
        icmp.set_echo_request(0x7af1, 0x123f)
        self.assertEquals(icmp.type, ICMP.Flags.ECHO_REQUEST)
        self.assertEquals(icmp.id, 0x7af1)
        self.assertEquals(icmp.sequence, 0x123f)

    def test_set_echo_reply(self):
        icmp = ICMP()
        icmp.set_echo_reply(0x7af1, 0x123f)
        self.assertEquals(icmp.type, ICMP.Flags.ECHO_REPLY)
        self.assertEquals(icmp.id, 0x7af1)
        self.assertEquals(icmp.sequence, 0x123f)

    def test_set_info_request(self):
        icmp = ICMP()
        icmp.set_info_request(0x7af1, 0x123f)
        self.assertEquals(icmp.type, ICMP.Flags.INFO_REQUEST)
        self.assertEquals(icmp.id, 0x7af1)
        self.assertEquals(icmp.sequence, 0x123f)

    def test_set_info_reply(self):
        icmp = ICMP()
        icmp.set_info_reply(0x7af1, 0x123f)
        self.assertEquals(icmp.type, ICMP.Flags.INFO_REPLY)
        self.assertEquals(icmp.id, 0x7af1)
        self.assertEquals(icmp.sequence, 0x123f)

    def test_unreach(self):
        icmp = ICMP()
        icmp.set_dest_unreachable()
        self.assertEquals(icmp.type, ICMP.Flags.DEST_UNREACHABLE)

    def test_time_exceed(self):
        icmp = ICMP()
        icmp.set_time_exceeded(1)
        self.assertEquals(icmp.type, ICMP.Flags.TIME_EXCEEDED)
        self.assertEquals(icmp.code, 0)
        icmp.set_time_exceeded(0)
        self.assertEquals(icmp.type, ICMP.Flags.TIME_EXCEEDED)
        self.assertEquals(icmp.code, 1)

    def test_param_problem(self):
        icmp = ICMP()

        icmp.set_param_problem(1, 0x4f)
        self.assertEquals(icmp.type, ICMP.Flags.PARAM_PROBLEM)
        self.assertEquals(icmp.code, 0)
        self.assertEquals(icmp.pointer, 0x4f)

        icmp.set_param_problem(False)
        self.assertEquals(icmp.type, ICMP.Flags.PARAM_PROBLEM)
        self.assertEquals(icmp.code, 1)

    def test_source_quench(self):
        icmp = ICMP()
        icmp.set_source_quench()
        self.assertEquals(icmp.type, ICMP.Flags.SOURCE_QUENCH)

    def test_redirect(self):
        icmp = ICMP()
        icmp.set_redirect(0x3d, "1.2.3.4")
        self.assertEquals(icmp.type, ICMP.Flags.REDIRECT)
        self.assertEquals(icmp.code, 0x3d)
        self.assertEquals(str(icmp.gateway), "1.2.3.4")

    def test_serialize(self):
        icmp1 = ICMP()
        icmp1.set_echo_request(0x34ab, 0x12f7)
        buf = icmp1.serialize()
        icmp2 = icmp1.copy()
        buf2 = icmp2.serialize()
        self.assertEquals(buf, buf2)

    def test_timestamp_match_resp(self):
        request = ICMP.from_buffer(ts_request)


# TEST_F(ICMPTest, TimestampMatchesResponse) {
#     ICMP request(ts_request, sizeof(ts_request));
#     EXPECT_TRUE(request.matches_response(ts_reply, sizeof(ts_reply)));
# }

    def test_constr_from_buffer(self):
        icmpA = ICMP.from_buffer(expected1)
        self.assertEquals(icmpA.type, ICMP.Flags.ECHO_REQUEST)
        self.assertEquals(icmpA.code, 1)
        self.assertEquals(icmpA.id, 0x56d1)
        self.assertEquals(icmpA.sequence, 0xf3b1)

        buf = icmpA.serialize()
        icmp_bis = ICMP.from_buffer(buf)
        check_equals(self, icmpA, icmp_bis)

        icmpB = ICMP.from_buffer(expected2)
        self.assertEquals(icmpB.type, ICMP.Flags.PARAM_PROBLEM)
        self.assertEquals(icmpB.code, 0)
        self.assertEquals(icmpB.pointer, 0x7f)

        buf = icmpB.serialize()
        icmp_bis = ICMP.from_buffer(buf)
        check_equals(self, icmpB, icmp_bis)

