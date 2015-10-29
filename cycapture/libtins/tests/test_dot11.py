# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, Dot11, RAW, PDUNotFound, UDP, OptionNotFound, Dot11Data, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)


class Resources(object):
    empty_addr = HWAddress()
    hw_addr = HWAddress("72:91:34:fa:de:ad")
    expected_packet = _f([53, 1, 79, 35, 0, 1, 2, 3, 4, 5])

    def check_equals(self, dot1, dot2):
        eq_(dot1.protocol, dot2.protocol)
        eq_(dot1.type, dot2.type)
        eq_(dot1.subtype, dot2.subtype)
        eq_(dot1.to_ds, dot2.to_ds)
        eq_(dot1.from_ds, dot2.from_ds)
        eq_(dot1.more_frag, dot2.more_frag)
        eq_(dot1.retry, dot2.retry)
        eq_(dot1.power_mgmt, dot2.power_mgmt)
        eq_(dot1.wep, dot2.wep)
        eq_(dot1.order, dot2.order)
        eq_(dot1.duration_id, dot2.duration_id)
        eq_(dot1.addr1, dot2.addr1)

    def check_empty(self, dot1):
        eq_(dot1.protocol, 0)
        eq_(dot1.to_ds, 0)
        eq_(dot1.from_ds, 0)
        eq_(dot1.more_frag, 0)
        eq_(dot1.retry, 0)
        eq_(dot1.power_mgmt, 0)
        eq_(dot1.wep, 0)
        eq_(dot1.order, 0)
        eq_(dot1.duration_id, 0)
        eq_(dot1.addr1, self.empty_addr)

class ResourcesData(Resources):

    expected_packet = _f([
        9, 0, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7,
        218, 241
    ])

    from_to_ds10 = _f([
        8, 2, 58, 1, 0, 37, 156, 116, 149, 146, 0, 24, 248, 245, 194, 198,
        0, 24, 248, 245, 194, 198, 64, 25, 170, 170, 3, 0, 0, 0, 136, 142,
        1, 3, 0, 95, 2, 0, 138, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 95, 85, 2,
        186, 64, 12, 215, 130, 122, 211, 219, 9, 59, 133, 92, 160, 245, 149,
        247, 123, 29, 204, 196, 41, 119, 233, 222, 169, 194, 225, 212, 18,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 60, 112, 49, 29
    ])

    from_to_ds01 = _f([
        8, 1, 202, 0, 0, 24, 248, 245, 194, 198, 0, 37, 156, 116, 149, 146, 0,
        24, 248, 245, 194, 198, 176, 124, 170, 170, 3, 0, 0, 0, 136, 142, 1, 3,
        0, 117, 2, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 253, 86, 38, 165, 150,
        136, 166, 218, 91, 179, 56, 214, 89, 91, 73, 149, 237, 147, 66, 222, 31,
        21, 190, 114, 129, 179, 254, 230, 168, 219, 145, 48, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 123, 221, 85, 85, 63, 11, 217, 173, 76, 120, 17, 34, 0, 228, 72,
        107, 0, 22, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0, 15, 172, 4, 1, 0, 0,
        15, 172, 2, 0, 0, 170, 11, 87, 71
    ])

    from_to_ds00 = _f([
        8, 0, 202, 0, 0, 24, 248, 245, 194, 198, 0, 37, 156, 116, 149, 146,
        0, 24, 248, 245, 194, 198, 176, 124, 170, 170, 3, 0, 0, 0, 136, 142,
        1, 3, 0, 117, 2, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 253, 86, 38,
        165, 150, 136, 166, 218, 91, 179, 56, 214, 89, 91, 73, 149, 237, 147,
        66, 222, 31, 21, 190, 114, 129, 179, 254, 230, 168, 219, 145, 48, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 123, 221, 85, 85, 63, 11, 217, 173, 76, 120,
        17, 34, 0, 228, 72, 107, 0, 22, 48, 20, 1, 0, 0, 15, 172, 2, 1, 0, 0,
        15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0, 170, 11, 87, 71
    ])

    def check_equals(self, dot1, dot2):
        eq_(dot1.addr2, dot2.addr2)
        eq_(dot1.addr3, dot2.addr3)
        eq_(dot1.addr4, dot2.addr4)
        eq_(dot1.frag_num, dot2.frag_num)
        eq_(dot1.seq_num, dot2.seq_num)
        super(ResourcesData, self).check_equals(dot1, dot2)

    def check_empty(self, dot1):
        eq_(dot1.addr2, self.empty_addr)
        eq_(dot1.addr3, self.empty_addr)
        eq_(dot1.addr4, self.empty_addr)
        eq_(dot1.frag_num, 0)
        eq_(dot1.seq_num, 0)
        super(ResourcesData, self).check_empty(dot1)

    def check_equals_expected(self, dot11):
        eq_(dot11.type, Dot11.Types.DATA)
        eq_(dot11.addr1, "00:01:02:03:04:05")
        eq_(dot11.addr2, "01:02:03:04:05:06")
        eq_(dot11.addr3, "02:03:04:05:06:07")
        eq_(dot11.frag_num, 0xa)
        eq_(dot11.seq_num, 0xf1d)


class Dot11Test(unittest.TestCase, Resources):

    def test_default_constr(self):
        dot = Dot11()
        eq_(dot.protocol, 0)
        eq_(dot.type, 0)
        eq_(dot.subtype, 0)
        eq_(dot.to_ds, 0)
        eq_(dot.from_ds, 0)
        eq_(dot.more_frag, 0)
        eq_(dot.retry, 0)
        eq_(dot.power_mgmt, 0)
        eq_(dot.wep, 0)
        eq_(dot.order, 0)
        eq_(dot.duration_id, 0)
        eq_(dot.addr1, self.empty_addr)

    def test_copy(self):
        dot1 = Dot11.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_constr_buf(self):
        dot = Dot11.from_buffer(self.expected_packet)
        eq_(dot.protocol, 1)
        eq_(dot.type, Dot11.Types.CONTROL)
        eq_(dot.subtype, 3)
        eq_(dot.to_ds, 1)
        eq_(dot.from_ds, 0)
        eq_(dot.more_frag, 0)
        eq_(dot.retry, 0)
        eq_(dot.power_mgmt, 0)
        eq_(dot.wep, 0)
        eq_(dot.order, 0)
        eq_(dot.duration_id, 0x234f)
        eq_(dot.addr1, "00:01:02:03:04:05")

    def test_src_addr_constr(self):
        dot = Dot11(self.hw_addr)
        eq_(dot.addr1, self.hw_addr)

    def test_protocol(self):
        dot = Dot11()
        dot.protocol = 1
        eq_(dot.protocol, 1)

    def test_type(self):
        dot = Dot11()
        dot.type = Dot11.Types.CONTROL
        eq_(dot.type, Dot11.Types.CONTROL)

    def test_subtype(self):
        dot = Dot11()
        dot.subtype = Dot11.DataSubtypes.QOS_DATA_DATA
        eq_(dot.subtype, Dot11.DataSubtypes.QOS_DATA_DATA)

    def test_to_ds(self):
        dot = Dot11()
        dot.to_ds = True
        eq_(dot.to_ds, True)

    def test_from_ds(self):
        dot = Dot11()
        dot.from_ds = True
        eq_(dot.from_ds, True)

    def test_more_frag(self):
        dot = Dot11()
        dot.more_frag = 1
        eq_(dot.more_frag, True)

    def test_retry(self):
        dot = Dot11()
        dot.retry = 1
        eq_(dot.retry, True)

    def test_power_mgmt(self):
        dot = Dot11()
        dot.power_mgmt = 1
        eq_(dot.power_mgmt, True)

    def test_wep(self):
        dot = Dot11()
        dot.wep = 1
        eq_(dot.wep, True)

    def test_order(self):
        dot = Dot11()
        dot.order = 1
        eq_(dot.order, True)

    def test_duration_id(self):
        dot = Dot11()
        dot.duration_id = 0x7163
        eq_(dot.duration_id, 0x7163)

    def test_addr1(self):
        dot = Dot11()
        dot.addr1 = self.hw_addr
        eq_(dot.addr1, self.hw_addr)

    def test_add_tagged_option(self):
        dot = Dot11()
        dot.add_option(Dot11.OptionTypes.SSID, self.hw_addr.to_bytes())
        opt = dot.search_option(Dot11.OptionTypes.SSID)
        ok_(len(opt) == 6)
        eq_(opt, self.hw_addr.to_bytes())

    def test_serialize(self):
        pdu = Dot11.from_buffer(self.expected_packet)
        buf = pdu.serialize()
        eq_(self.expected_packet, buf)


class Dot11DataTest(unittest.TestCase, ResourcesData):
    def test_constr(self):
        dot11 = Dot11Data()
        self.check_empty(dot11)

    def test_constr_buf(self):
        dot11 = Dot11Data.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11Data.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_fragnum(self):
        dot11 = Dot11Data()
        dot11.frag_num = 0x3
        eq_(dot11.frag_num, 0x3)
        eq_(dot11.seq_num, 0)

    def test_seqnum(self):
        dot11 = Dot11Data()
        dot11.seq_num = 0x1f2
        eq_(dot11.seq_num, 0x1f2)
        eq_(dot11.frag_num, 0)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        eq_(dot11.pdu_type, PDU.DOT11_DATA)
        self.check_equals_expected(dot11)

    def test_pcapload1(self):
        buf = _f([
            8, 66, 212, 0, 0, 36, 33, 146, 167, 83, 0, 27, 17, 210, 27, 235, 0,
            27, 17, 210, 27, 235, 144, 121, 163, 95, 0, 32, 0, 0, 0, 0, 240, 239,
            181, 249, 52, 203, 0, 44, 68, 228, 186, 34, 167, 47, 47, 71, 4, 213,
            111, 78, 235, 54, 91, 195, 68, 116, 121, 236, 132, 242, 96, 32, 88,
            30, 112, 162, 122, 2, 26, 55, 210, 242, 10, 28, 199, 122, 68, 196,
            196, 188, 71, 95, 159, 207, 188, 162, 183, 175, 237, 224, 204, 185,
            158, 148, 32, 238, 70, 137, 49, 171, 231, 184, 73, 175, 195, 244, 197,
            149, 28, 141, 26, 248, 58, 189, 149, 191, 121, 206, 218, 120, 115,
            64, 224, 62, 161, 66, 148, 217, 177, 166, 23, 238, 180, 149, 69
        ])

        dot1 = Dot11Data.from_buffer(buf)
        eq_(dot1.addr1, "00:24:21:92:a7:53")
        eq_(dot1.addr2, "00:1b:11:d2:1b:eb")
        eq_(dot1.addr3, "00:1b:11:d2:1b:eb")
        eq_(dot1.wep, 1)
        eq_(dot1.from_ds, 1)
        eq_(dot1.frag_num, 0)
        eq_(dot1.seq_num, 1945)

        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_serialize(self):
        pdu = Dot11Data.from_buffer(self.expected_packet)
        buf = pdu.serialize()
        eq_(self.expected_packet, buf)

    def test_source_bssid_addr1(self):
        data = Dot11Data.from_buffer(self.from_to_ds10)
        eq_(data.from_ds, 1)
        eq_(data.to_ds, 0)
        eq_(data.src_addr, "00:18:f8:f5:c2:c6")
        eq_(data.dst_addr, "00:25:9c:74:95:92")
        eq_(data.bssid_addr, "00:18:f8:f5:c2:c6")

    def test_source_bssid_addr2(self):
        data = Dot11Data.from_buffer(self.from_to_ds01)
        eq_(data.from_ds, 0)
        eq_(data.to_ds, 1)
        eq_(data.src_addr, "00:25:9c:74:95:92")
        eq_(data.dst_addr, "00:18:f8:f5:c2:c6")
        eq_(data.bssid_addr, "00:18:f8:f5:c2:c6")

    def test_source_bssid_addr3(self):
        data = Dot11Data.from_buffer(self.from_to_ds00)
        eq_(data.from_ds, 0)
        eq_(data.to_ds, 0)
        eq_(data.src_addr, "00:25:9c:74:95:92")
        eq_(data.dst_addr, "00:18:f8:f5:c2:c6")
        eq_(data.bssid_addr, "00:18:f8:f5:c2:c6")

