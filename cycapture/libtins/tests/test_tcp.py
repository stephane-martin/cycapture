# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"


def _f(packet):
    return "".join(chr(i) for i in packet)


def check_equals(obj, tcp1, tcp2):
    obj.assertEquals(tcp1.dport, tcp2.dport)
    obj.assertEquals(tcp2.sport, tcp2.sport)
    obj.assertEquals(tcp1.seq, tcp2.seq)
    obj.assertEquals(tcp1.ack_seq, tcp2.ack_seq)
    obj.assertEquals(tcp1.window, tcp2.window)
    obj.assertEquals(tcp1.checksum, tcp2.checksum)
    obj.assertEquals(tcp1.urg_ptr, tcp2.urg_ptr)
    obj.assertEquals(tcp1.data_offset, tcp2.data_offset)
    obj.assertEquals(tcp1.ref_inner_pdu() is None, tcp2.ref_inner_pdu() is None)


expected_packet = _f([
    127, 77, 79, 29, 241, 218, 229, 70, 95, 174, 209, 35, 208, 2, 113,
    218, 0, 0, 31, 174, 2, 4, 152, 250, 8, 10, 79, 210, 58, 203, 137, 254,
    18, 52, 3, 3, 122, 4, 2, 5, 10, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0
])

checksum_packet = _f([
    69, 0, 0, 40, 0, 0, 64, 0, 64, 6, 60, 206, 0, 0, 0, 0, 127, 0, 0, 1,
    5, 57, 199, 49, 0, 0, 0, 0, 255, 216, 70, 222, 80, 20, 0, 0, 158, 172,
    0, 0
])


class TCPTest(unittest.TestCase):
    def test_default_constructor(self):
        tcp = TCP()
        self.assertEquals(tcp.dport, 0)
        self.assertEquals(tcp.sport, 0)
        self.assertEquals(tcp.pdu_type, PDU.TCP)

    def test_checksum(self):
        pkt1 = IP.from_buffer(checksum_packet)
        tcp1 = pkt1.rfind_pdu(TCP)
        checksum = tcp1.checksum

        buf = pkt1.serialize()
        pkt2 = IP.from_buffer(buf)
        tcp2 = pkt2.rfind_pdu(TCP)
        self.assertEquals(checksum, tcp2.checksum)
        self.assertEquals(tcp1.checksum, tcp2.checksum)

    def test_copy_constructor(self):
        tcp1 = TCP(0x6d1f, 0x78f2)
        tcp2 = tcp1.copy()
        check_equals(self, tcp1, tcp2)

    def test_nested_copy(self):
        nested_tcp = TCP(0x6d1f, 0x78f2)
        tcp1 = TCP(0x6d1f, 0x78f2)
        tcp1.set_inner_pdu(nested_tcp)
        tcp2 = tcp1.copy()
        check_equals(self, tcp1, tcp2)

    def test_complete_constructor(self):
        tcp = TCP(0x6d1f, 0x78f2)
        self.assertEquals(tcp.dport, 0x6d1f)
        self.assertEquals(tcp.sport, 0x78f2)

    def test_dport(self):
        tcp = TCP()
        tcp.dport = 0x5fad
        self.assertEquals(tcp.dport, 0x5fad)

    def test_sport(self):
        tcp = TCP()
        tcp.sport = 0x5fad
        self.assertEquals(tcp.sport, 0x5fad)

    def test_seq(self):
        tcp = TCP()
        tcp.seq = 0x5fad65fb
        self.assertEquals(tcp.seq, 0x5fad65fb)

    def test_ackseq(self):
        tcp = TCP()
        tcp.ack_seq = 0x5fad65fb
        self.assertEquals(tcp.ack_seq, 0x5fad65fb)

    def test_window(self):
        tcp = TCP()
        tcp.window = 0x5fad
        self.assertEquals(tcp.window, 0x5fad)

    def test_urg(self):
        tcp = TCP()
        tcp.urg_ptr = 0x5fad
        self.assertEquals(tcp.urg_ptr, 0x5fad)

    def test_data_offset(self):
        tcp = TCP()
        tcp.data_offset = 0xe
        self.assertEquals(tcp.data_offset, 0xe)

    def test_set_flag(self):
        tcp = TCP()

        tcp.syn_flag = 1
        tcp.set_flag(TCP.Flags.FIN, 1)

        self.assertTrue(tcp.get_flag(TCP.Flags.SYN))
        self.assertTrue(tcp.fin_flag)
        self.assertTrue(not tcp.rst_flag)
        self.assertTrue(not tcp.psh_flag)
        self.assertTrue(not tcp.ack_flag)
        self.assertTrue(not tcp.urg_flag)
        self.assertTrue(not tcp.ece_flag)
        self.assertTrue(not tcp.cwr_flag)

    def test_flags(self):
        tcp = TCP()
        tcp.syn_flag = True
        tcp.fin_flag = 1
        self.assertEquals(tcp.flags, TCP.Flags.SYN | TCP.Flags.FIN)

        tcp.flags = TCP.Flags.PSH | TCP.Flags.RST
        self.assertEquals(tcp.flags, TCP.Flags.PSH | TCP.Flags.RST)

    def test_mss(self):
        tcp = TCP()
        tcp.mss = 0x456f
        self.assertEquals(tcp.mss, 0x456f)

    def test_window_scale(self):
        tcp = TCP()
        tcp.winscale = 0x4f
        self.assertEquals(tcp.winscale, 0x4f)

    def test_sack_permitted(self):
        tcp = TCP()
        tcp.set_sack_permitted()
        self.assertTrue(tcp.sack_permitted)

    def test_sack(self):
        tcp = TCP()
        tcp.sack = [0x13, 0x63fa1d7a, 0xff1c]
        self.assertEquals(tcp.sack, [0x13, 0x63fa1d7a, 0xff1c])

    def test_alternate_checksum(self):
        tcp = TCP()
        tcp.altchecksum = TCP.AltChecksums.CHK_16FLETCHER
        self.assertEquals(tcp.altchecksum, TCP.AltChecksums.CHK_16FLETCHER)

    def test_timestamp(self):
        tcp = TCP()
        tcp.timestamp = (0x456fa23d, 0xfa12d345)
        val, rep = tcp.timestamp
        self.assertEquals(val, 0x456fa23d)
        self.assertEquals(rep, 0xfa12d345)

