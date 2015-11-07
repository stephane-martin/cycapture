# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
from .. import fh_pattern, HWAddress, PDU, Dot11, channel_switch_t, Dot11Ack, Dot11BlockAckRequest, country_params, Dot11Data
from .. import Dot11Authentication, Dot11Deauthentication, Dot11RTS, Dot11PSPoll, Dot11Beacon, cf_params, dfs_params, quiet_t, tim_t
from .. import RSNInformation, Dot11CFEnd, Dot11EndCFAck, Dot11Disassoc, Dot11AssocRequest, Dot11AssocResponse, Dot11ReAssocRequest
from .. import Dot11ReAssocResponse, Dot11ProbeRequest, Dot11ProbeResponse


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

    def check_empty(self, dot11):
        eq_(dot11.protocol, 0)
        eq_(dot11.to_ds, 0)
        eq_(dot11.from_ds, 0)
        eq_(dot11.more_frag, 0)
        eq_(dot11.retry, 0)
        eq_(dot11.power_mgmt, 0)
        eq_(dot11.wep, 0)
        eq_(dot11.order, 0)
        eq_(dot11.duration_id, 0)
        eq_(dot11.addr1, self.empty_addr)

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

class ResourcesAck(Resources):
    expected_packet = _f([213, 1, 79, 35, 0, 1, 2, 3, 4, 5])

    def check_equals_expected(self, dot11):
        eq_(dot11.protocol, 1)
        eq_(dot11.type, Dot11.Types.CONTROL)
        eq_(dot11.subtype, Dot11.ControlSubtypes.ACK)
        eq_(dot11.to_ds, 1)
        eq_(dot11.from_ds, 0)
        eq_(dot11.more_frag, 0)
        eq_(dot11.retry, 0)
        eq_(dot11.power_mgmt, 0)
        eq_(dot11.wep, 0)
        eq_(dot11.order, 0)
        eq_(dot11.duration_id, 0x234f)
        eq_(dot11.addr1, "00:01:02:03:04:05")


class Dot11AckTest(unittest.TestCase, ResourcesAck):
    def test_constr(self):
        dot11 = Dot11Ack()
        self.check_empty(dot11)
        eq_(dot11.protocol, 0)
        eq_(dot11.type, Dot11.Types.CONTROL)
        eq_(dot11.subtype, Dot11.ControlSubtypes.ACK)
        eq_(dot11.to_ds, 0)
        eq_(dot11.from_ds, 0)
        eq_(dot11.more_frag, 0)
        eq_(dot11.retry, 0)
        eq_(dot11.power_mgmt, 0)
        eq_(dot11.wep, 0)
        eq_(dot11.order, 0)
        eq_(dot11.duration_id, 0)
        eq_(dot11.addr1, self.empty_addr)

    def test_constr_buf(self):
        dot11 = Dot11Ack.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11Ack.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_serialize(self):
        dot11 = Dot11Ack.from_buffer(self.expected_packet)
        buf = dot11.serialize()
        eq_(self.expected_packet, buf)


class ResourcesControlTA(Resources):
    def check_equals(self, dot1, dot2):
        eq_(dot1.target_addr, dot2.target_addr)
        super(ResourcesControlTA, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        eq_(dot11.target_addr, "01:02:03:04:05:06")
        eq_(dot11.addr1, "00:01:02:03:04:05")

    def check_empty(self, dot11):
        eq_(dot11.target_addr, self.empty_addr)
        eq_(dot11.addr1, self.empty_addr)


class ResourcesBlockAckRequest(ResourcesControlTA):
    expected_packet = _f([132, 0, 176, 1, 0, 33, 107, 2, 154, 230, 0, 28, 223, 215, 13, 85, 4, 0, 176, 33])

    def check_equals(self, dot1, dot2):
        eq_(dot1.fragment_number, dot2.fragment_number)
        eq_(dot1.start_sequence, dot2.start_sequence)
        eq_(dot1.bar_control, dot2.bar_control)

    def check_equals_expected(self, dot11):
        eq_(dot11.type, Dot11.Types.CONTROL)
        eq_(dot11.subtype, Dot11.ControlSubtypes.BLOCK_ACK_REQ)
        eq_(dot11.bar_control, 4)
        eq_(dot11.start_sequence, 539)
        eq_(dot11.fragment_number, 0)

class BlockAckRequestTest(unittest.TestCase, ResourcesBlockAckRequest):
    def test_constr(self):
        dot11 = Dot11BlockAckRequest()
        self.check_empty(dot11)
        eq_(dot11.subtype, Dot11.ControlSubtypes.BLOCK_ACK_REQ)
        eq_(dot11.fragment_number, 0)
        eq_(dot11.start_sequence, 0)
        eq_(dot11.bar_control, 0)

    def test_constr_buf(self):
        dot11 = Dot11BlockAckRequest.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11BlockAckRequest()
        dot1.fragment_number = 6
        dot1.start_sequence = 0x294
        dot1.bar_control = 0x9
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_serialize(self):
        dot11 = Dot11BlockAckRequest.from_buffer(self.expected_packet)
        buf = dot11.serialize()
        eq_(buf, self.expected_packet)


class ResourcesManagement(Resources):
    def check_equals(self, dot1, dot2):
        eq_(dot1.addr2, dot2.addr2)
        eq_(dot1.addr3, dot2.addr3)
        eq_(dot1.addr4, dot2.addr4)
        eq_(dot1.frag_num, dot2.frag_num)
        eq_(dot1.seq_num, dot2.seq_num)
        super(ResourcesManagement, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        eq_(dot11.protocol, 1)
        eq_(dot11.type, Dot11.Types.MANAGEMENT)
        eq_(dot11.to_ds, 1)
        eq_(dot11.from_ds, 0)
        eq_(dot11.more_frag, 0)
        eq_(dot11.retry, 0)
        eq_(dot11.power_mgmt, 0)
        eq_(dot11.wep, 0)
        eq_(dot11.order, 0)
        eq_(dot11.duration_id, 0x234f)
        eq_(dot11.addr1, "00:01:02:03:04:05")
        eq_(dot11.addr2, "01:02:03:04:05:06")
        eq_(dot11.addr3, "02:03:04:05:06:07")

    def check_empty(self, dot11):
        eq_(dot11.type, Dot11.Types.MANAGEMENT)
        eq_(dot11.addr2, self.empty_addr)
        eq_(dot11.addr3, self.empty_addr)
        eq_(dot11.addr4, self.empty_addr)
        eq_(dot11.frag_num, 0)
        eq_(dot11.seq_num, 0)

        super(ResourcesManagement, self).check_empty(dot11)

    def check_capinfo_equals(self, info1, info2):
        eq_(info1.ess, info2.ess)
        eq_(info1.ibss, info2.ibss)
        eq_(info1.cf_poll, info2.cf_poll)
        eq_(info1.cf_poll_req, info2.cf_poll_req)
        eq_(info1.privacy, info2.privacy)
        eq_(info1.short_preamble, info2.short_preamble)
        eq_(info1.pbcc, info2.pbcc)
        eq_(info1.channel_agility, info2.channel_agility)
        eq_(info1.spectrum_mgmt, info2.spectrum_mgmt)
        eq_(info1.qos, info2.qos)
        eq_(info1.sst, info2.sst)
        eq_(info1.apsd, info2.apsd)
        eq_(info1.reserved, info2.reserved)
        eq_(info1.dsss_ofdm, info2.dsss_ofdm)
        eq_(info1.delayed_block_ack, info2.delayed_block_ack)
        eq_(info1.immediate_block_ack, info2.immediate_block_ack)

    def check_capinfo_empty(self, info):
        eq_(info.ess, 0)
        eq_(info.ibss, 0)
        eq_(info.cf_poll, 0)
        eq_(info.cf_poll_req, 0)
        eq_(info.privacy, 0)
        eq_(info.short_preamble, 0)
        eq_(info.pbcc, 0)
        eq_(info.channel_agility, 0)
        eq_(info.spectrum_mgmt, 0)
        eq_(info.qos, 0)
        eq_(info.sst, 0)
        eq_(info.apsd, 0)
        eq_(info.reserved, 0)
        eq_(info.dsss_ofdm, 0)
        eq_(info.delayed_block_ack, 0)
        eq_(info.immediate_block_ack, 0)



class ResourcesAuth(ResourcesManagement):
    expected_packet = _f([177, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 162, 40, 58, 242, 243, 146])

    def check_equals(self, dot1, dot2):
        eq_(dot1.status_code, dot2.status_code)
        eq_(dot1.auth_seq_number, dot2.auth_seq_number)
        eq_(dot1.auth_algorithm, dot2.auth_algorithm)

        super(ResourcesAuth, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        super(ResourcesAuth, self).check_equals_expected(dot11)
        eq_(dot11.status_code, 0x92f3)
        eq_(dot11.auth_seq_number, 0xf23a)
        eq_(dot11.auth_algorithm, 0x28a2)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.AUTH)

class Dot11AuthenticationTest(unittest.TestCase, ResourcesAuth):
    def test_constr(self):
        dot11 = Dot11Authentication()
        self.check_empty(dot11)
        eq_(dot11.status_code, 0)
        eq_(dot11.auth_seq_number, 0)
        eq_(dot11.auth_algorithm, 0)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.AUTH)

    def test_constr_buf(self):
        dot11 = Dot11Authentication.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11Authentication.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_status_code(self):
        dot11 = Dot11Authentication()
        dot11.status_code = 0x92f3
        eq_(dot11.status_code, 0x92f3)

    def test_auth_seq_num(self):
        dot11 = Dot11Authentication()
        dot11.auth_seq_number = 0x92f3
        eq_(dot11.auth_seq_number, 0x92f3)

    def test_auth_alg(self):
        dot11 = Dot11Authentication()
        dot11.auth_algorithm = 0x92f3
        eq_(dot11.auth_algorithm, 0x92f3)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        eq_(type(dot11), Dot11Authentication)
        self.check_equals_expected(dot11)

    def test_serialize(self):
        dot11 = Dot11Authentication.from_buffer(self.expected_packet)
        buf = dot11.serialize()
        eq_(self.expected_packet, buf)


class ResourcesDeAuth(ResourcesManagement):
    expected_packet = _f([193, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 243, 146])

    def check_equals(self, dot1, dot2):
        eq_(dot1.reason_code, dot2.reason_code)
        super(ResourcesDeAuth, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        super(ResourcesDeAuth, self).check_equals_expected(dot11)
        eq_(dot11.reason_code, 0x92f3)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.DEAUTH)

class Dot11DeAuthenticationTest(unittest.TestCase, ResourcesDeAuth):
    def test_constr(self):
        dot11 = Dot11Deauthentication()
        self.check_empty(dot11)
        eq_(dot11.reason_code, 0)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.DEAUTH)

    def test_constr_buf(self):
        dot11 = Dot11Deauthentication.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11Deauthentication.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_reason_code(self):
        dot11 = Dot11Deauthentication()
        dot11.reason_code = 0x92f3
        eq_(dot11.reason_code, 0x92f3)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        eq_(type(dot11), Dot11Deauthentication)
        self.check_equals_expected(dot11)

    def test_serialize(self):
        dot11 = Dot11Deauthentication.from_buffer(self.expected_packet)
        buf = dot11.serialize()
        eq_(self.expected_packet, buf)


class ResourcesRTS(ResourcesControlTA):
    expected_packet = _f([181, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6])

    def check_equals_expected(self, dot11):
        eq_(dot11.subtype, Dot11.ControlSubtypes.RTS)
        super(ResourcesRTS, self).check_equals_expected(dot11)


class Dot11RTSTest(unittest.TestCase, ResourcesRTS):
    def test_constr(self):
        dot11 = Dot11RTS()
        self.check_empty(dot11)
        eq_(dot11.subtype, Dot11.ControlSubtypes.RTS)

    def test_constr_buf(self):
        dot11 = Dot11RTS.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11RTS.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11RTS))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        pdu = Dot11RTS.from_buffer(self.expected_packet)
        buf = pdu.serialize()
        eq_(self.expected_packet, buf)


class ResourcesPSPoll(ResourcesControlTA):
    expected_packet = _f([165, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6])

    def check_equals_expected(self, dot11):
        eq_(dot11.subtype, Dot11.ControlSubtypes.PS)
        super(ResourcesPSPoll, self).check_equals_expected(dot11)

class Dot11PSPollTest(unittest.TestCase, ResourcesPSPoll):
    def test_constr(self):
        dot11 = Dot11PSPoll()
        self.check_empty(dot11)
        eq_(dot11.subtype, Dot11.ControlSubtypes.PS)

    def test_constr_buf(self):
        dot11 = Dot11PSPoll.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11PSPoll.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11PSPoll))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        buf = dot11.serialize()
        eq_(buf, self.expected_packet)



class ResourcesBeacon(ResourcesManagement):
    hwaddr = "72:91:34:fa:de:ad"
    expected_packet = _f([129, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 250, 1, 147, 40,
                          65, 35, 173, 31, 250, 20, 149, 32])

    def check_equals_expected(self, dot11):
        eq_(dot11.subtype, 8)
        eq_(dot11.timestamp, 0x1fad2341289301fa)
        eq_(dot11.interval, 0x14fa)

        info = dot11.capabilities
        eq_(info.ess, 1)
        eq_(info.ibss, 0)
        eq_(info.cf_poll, 1)
        eq_(info.cf_poll_req, 0)
        eq_(info.privacy, 1)
        eq_(info.short_preamble, 0)
        eq_(info.pbcc, 0)
        eq_(info.channel_agility, 1)
        eq_(info.spectrum_mgmt, 0)
        eq_(info.qos, 0)
        eq_(info.sst, 0)
        eq_(info.apsd, 0)
        eq_(info.reserved, 0)
        eq_(info.dsss_ofdm, 1)
        eq_(info.delayed_block_ack, 0)
        eq_(info.immediate_block_ack, 0)

        super(ResourcesBeacon, self).check_equals_expected(dot11)

    def check_equals(self, dot1, dot2):
        eq_(dot1.interval, dot2.interval)
        eq_(dot1.timestamp, dot2.timestamp)

        self.check_capinfo_equals(dot1.capabilities, dot2.capabilities)
        super(ResourcesBeacon, self).check_equals(dot1, dot2)


class Dot11BeaconTest(unittest.TestCase, ResourcesBeacon):
    def test_constr(self):
        dot11 = Dot11Beacon()
        self.check_empty(dot11)
        self.check_capinfo_empty(dot11.capabilities)
        eq_(dot11.interval, 0)
        eq_(dot11.timestamp, 0)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.BEACON)

    def test_constr_buf(self):
        dot11 = Dot11Beacon.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11Beacon.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_frag_num(self):
        dot11 = Dot11Beacon()
        dot11.frag_num = 0x3
        eq_(dot11.frag_num, 0x3)
        eq_(dot11.seq_num, 0)

    def test_seq_num(self):
        dot11 = Dot11Beacon()
        dot11.seq_num = 0x1f2
        eq_(dot11.seq_num, 0x1f2)
        eq_(dot11.frag_num, 0)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11Beacon))
        self.check_equals_expected(dot11)

    def test_ts(self):
        dot11 = Dot11Beacon()
        dot11.timestamp = 0x1fad2341289301fa
        eq_(dot11.timestamp, 0x1fad2341289301fa)

    def test_interval(self):
        dot11 = Dot11Beacon()
        dot11.interval = 0x14fa
        eq_(dot11.interval, 0x14fa)

    def test_ssid(self):
        dot11 = Dot11Beacon()
        dot11.ssid = "libtins"
        eq_(dot11.ssid, "libtins")

    def test_supported_rates(self):
        dot11 = Dot11Beacon()
        dot11.supported_rates = [0.5, 1.0, 5.5, 7.5]
        eq_(dot11.supported_rates, [0.5, 1.0, 5.5, 7.5])

    def test_ext_supported_rates(self):
        dot11 = Dot11Beacon()
        dot11.extended_supported_rates = [0.5, 1.0, 5.5, 7.5]
        eq_(dot11.extended_supported_rates, [0.5, 1.0, 5.5, 7.5])

    def test_qos_cap(self):
        dot11 = Dot11Beacon()
        dot11.qos_capability = 0xfa
        eq_(dot11.qos_capability, 0xfa)

    def test_power_cap(self):
        dot11 = Dot11Beacon()
        dot11.power_capability = (0xfa, 0xa2)
        eq_(dot11.power_capability, (0xfa, 0xa2))

    def test_supported_channels(self):
        dot11 = Dot11Beacon()
        dot11.supported_channels = [(13, 19), (67, 159)]
        eq_(dot11.supported_channels, [(13, 19), (67, 159)])

    def test_req_info(self):
        dot11 = Dot11Beacon()
        dot11.request_information = [10, 15, 51, 42]
        eq_(dot11.request_information, [10, 15, 51, 42])

    def test_fh_param_set(self):
        dot11 = Dot11Beacon()
        dot11.fh_parameter_set = (0x482f, 67, 42, 0xa1)
        params = dot11.fh_parameter_set
        eq_(params.dwell_time, 0x482f)
        eq_(params.hop_set, 67)
        eq_(params.hop_pattern, 42)
        eq_(params.hop_index, 0xa1)

    def test_ds_param_set(self):
        dot11 = Dot11Beacon()
        dot11.ds_parameter_set = 0x1e
        eq_(dot11.ds_parameter_set, 0x1e)

    def test_cf_param_set(self):
        dot11 = Dot11Beacon()
        s = cf_params(67, 42, 0x482f, 0x9af1)
        dot11.cf_parameter_set = s
        eq_(dot11.cf_parameter_set, s)

    def test_ibss_param_set(self):
        dot11 = Dot11Beacon()
        dot11.ibss_parameter_set = 0x1ef3
        eq_(dot11.ibss_parameter_set, 0x1ef3)

    def test_ibss_dfs(self):
        dot11 = Dot11Beacon()
        dfs = dfs_params(
            HWAddress("00:01:02:03:04:05"),
            0x7f,
            [(0x8e, 0x92), (0x02, 0xf2), (0x02, 0xf2)]
        )
        dot11.ibss_dfs = dfs
        eq_(dot11.ibss_dfs, dfs)

    def test_country(self):
        dot11 = Dot11Beacon()
        c = country_params(
            "US ",
            [65, 11, 97],
            [123, 56, 42],
            [4, 213, 165]
        )
        dot11.country = c
        eq_(dot11.country, c)

    def test_fh_parameters(self):
        dot11 = Dot11Beacon()
        dot11.fh_parameters = (0x42, 0x1f)
        eq_(dot11.fh_parameters, (0x42, 0x1f))

    def test_fh_pattern(self):
        dot11 = Dot11Beacon()
        tim = fh_pattern(
            0x67,
            0x42,
            0x1f,
            0x3a,
            [23, 15, 129]
        )
        dot11.fh_pattern_table = tim
        eq_(dot11.fh_pattern_table, tim)

    def test_power_constraint(self):
        dot11 = Dot11Beacon()
        dot11.power_constraint = 0x1e
        eq_(dot11.power_constraint, 0x1e)

    def test_channel_switch(self):
        dot11 = Dot11Beacon()
        dot11.channel_switch = [13, 42, 98]
        eq_(dot11.channel_switch, channel_switch_t(13, 42, 98))

    def test_quiet(self):
        dot11 = Dot11Beacon()
        dot11.quiet = (13, 42, 0x928f, 0xf1ad)
        eq_(dot11.quiet, quiet_t(13, 42, 0x928f, 0xf1ad))

    def test_tpc_report(self):
        dot11 = Dot11Beacon()
        dot11.tpc_report = (42, 193)
        eq_(dot11.tpc_report, (42, 193))

    def test_erp_info(self):
        dot11 = Dot11Beacon()
        dot11.erp_information = 0x1e
        eq_(dot11.erp_information, 0x1e)

    def test_bssload(self):
        dot11 = Dot11Beacon()
        dot11.bss_load = (0x129f, 42, 0xf5a2)
        eq_(dot11.bss_load.station_count, 0x129f)
        eq_(dot11.bss_load.channel_utilization, 42)
        eq_(dot11.bss_load.available_capacity, 0xf5a2)

    def test_tim(self):
        dot11 = Dot11Beacon()
        t = tim_t(
            42,
            59,
            191,
            [92, 182, 212]
        )
        dot11.tim = t
        eq_(dot11.tim, t)

    def test_challenge_text(self):
        dot11 = Dot11Beacon()
        dot11.challenge_text = "libtins ftw"
        eq_(dot11.challenge_text, "libtins ftw")

    def test_vendor_specific(self):
        dot11 = Dot11Beacon()
        dot11.vendor_specific = ("03:03:02", [0x22, 0x35])
        eq_(dot11.vendor_specific.oui, "03:03:02")
        eq_(dot11.vendor_specific.data, [0x22, 0x35])

    def test_rsn_info_test(self):
        rsn_info = RSNInformation()
        rsn_info.add_pairwise_cypher(RSNInformation.CypherSuites.WEP_40)
        rsn_info.add_akm_cypher(RSNInformation.AKMSuites.PSK)
        rsn_info.group_suite = RSNInformation.CypherSuites.CCMP
        rsn_info.version = 0x7283
        rsn_info.capabilities = 0x18ad

        dot11 = Dot11Beacon()
        dot11.rsn_information = rsn_info
        found = dot11.rsn_information
        eq_(rsn_info.version, found.version)
        eq_(rsn_info.capabilities, found.capabilities)
        eq_(rsn_info.group_suite, found.group_suite)
        eq_(rsn_info.get_pairwise_cyphers(), found.get_pairwise_cyphers())
        eq_(rsn_info.get_akm_cyphers(), found.get_akm_cyphers())

    def test_serialize(self):
        pdu = Dot11Beacon.from_buffer(self.expected_packet)
        buf = pdu.serialize()
        eq_(self.expected_packet, buf)

    def test_pcap_load1(self):
        buf = _f([
            128, 0, 0, 0, 255, 255, 255, 255, 255, 255, 244, 236, 56, 254, 77,
            146, 244, 236, 56, 254, 77, 146, 224, 234, 128, 209, 212, 206, 44,
            0, 0, 0, 100, 0, 49, 4, 0, 7, 83, 101, 103, 117, 110, 100, 111, 1,
            8, 130, 132, 139, 150, 12, 18, 24, 36, 3, 1, 1, 5, 4, 0, 1, 0, 0, 7,
            6, 85, 83, 32, 1, 13, 20, 42, 1, 0, 48, 20, 1, 0, 0, 15, 172, 4, 1,
            0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0, 50, 4, 48, 72, 96, 108,
            221, 24, 0, 80, 242, 2, 1, 1, 3, 0, 3, 164, 0, 0, 39, 164, 0, 0, 66,
            67, 94, 0, 98, 50, 47, 0, 221, 9, 0, 3, 127, 1, 1, 0, 0, 255, 127
        ])
        dot11 = Dot11Beacon.from_buffer(buf)
        rates = [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0]
        ext_rates = [24.0, 36.0, 48.0, 54.0]
        rates_parsed = dot11.supported_rates
        ext_rates_parsed = dot11.extended_supported_rates
        tim = tim_t(0, 1, 0, [0])
        tim_parsed = dot11.tim
        c = country_params(
            "US ",
            [1],
            [13],
            [20]
        )
        country_parsed = dot11.country
        eq_(dot11.ssid, "Segundo")
        eq_(rates, rates_parsed)
        eq_(ext_rates, ext_rates_parsed)
        eq_(dot11.ds_parameter_set, 1)
        eq_(tim, tim_parsed)
        eq_(c, country_parsed)
        eq_(dot11.erp_information, 0)

    def test_tim2(self):
        dot11 = Dot11Beacon()
        tim = tim_t(0, 1, 0, [1])
        dot11.tim = tim
        eq_(dot11.tim, tim)

class ResourcesCFEnd(ResourcesControlTA):
    expected_packet = _f([229, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6])

    def check_equals_expected(self, dot11):
        eq_(dot11.subtype, Dot11.ControlSubtypes.CF_END)
        super(ResourcesCFEnd, self).check_equals_expected(dot11)

class CFEndTest(unittest.TestCase, ResourcesCFEnd):
    def test_constr(self):
        dot11 = Dot11CFEnd()
        self.check_empty(dot11)
        eq_(dot11.subtype, Dot11.ControlSubtypes.CF_END)

    def test_constr_buf(self):
        dot11 = Dot11CFEnd.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11CFEnd.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11CFEnd))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        dot11 = Dot11CFEnd.from_buffer(self.expected_packet)
        buf = dot11.serialize()
        eq_(self.expected_packet, buf)



class ResourcesCFEndACK(ResourcesControlTA):
    expected_packet = _f([245, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6])

    def check_equals_expected(self, dot11):
        eq_(dot11.subtype, Dot11.ControlSubtypes.CF_END_ACK)
        super(ResourcesCFEndACK, self).check_equals_expected(dot11)


class CFEndACKTest(unittest.TestCase, ResourcesCFEndACK):
    def test_constr(self):
        dot11 = Dot11EndCFAck()
        self.check_empty(dot11)
        eq_(dot11.subtype, Dot11.ControlSubtypes.CF_END_ACK)

    def test_constr_buf(self):
        dot11 = Dot11EndCFAck.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11EndCFAck.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11EndCFAck))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        dot11 = Dot11EndCFAck.from_buffer(self.expected_packet)
        buf = dot11.serialize()
        eq_(self.expected_packet, buf)


class ResourcesDisassoc(ResourcesManagement):
    expected_packet = _f([161, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 18, 35])

    def check_equals(self, dot1, dot2):
        eq_(dot1.reason_code, dot2.reason_code)
        super(ResourcesDisassoc, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        eq_(dot11.reason_code, 0x2312)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.DISASSOC)

class Dot11DisassocTest(unittest.TestCase, ResourcesDisassoc):
    def test_constr(self):
        dot11 = Dot11Disassoc()
        self.check_empty(dot11)
        eq_(dot11.reason_code, 0)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.DISASSOC)

    def test_constr_buf(self):
        dot11 = Dot11Disassoc.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11Disassoc.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_reason_code(self):
        dot11 = Dot11Disassoc()
        dot11.reason_code = 0x92f3
        eq_(dot11.reason_code, 0x92f3)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11Disassoc))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        dot11 = Dot11Disassoc.from_buffer(self.expected_packet)
        buf = dot11.serialize()
        eq_(self.expected_packet, buf)

class ResourcesAssocRequest(ResourcesManagement):
    expected_packet = _f([1, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 21, 32, 243, 146])

    def check_equals(self, dot1, dot2):
        self.check_capinfo_equals(dot1.capabilities, dot2.capabilities)
        eq_(dot1.listen_interval, dot2.listen_interval)
        super(ResourcesAssocRequest, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        eq_(dot11.listen_interval, 0x92f3)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.ASSOC_REQ)
        super(ResourcesAssocRequest, self).check_equals_expected(dot11)

class Dot11AssocRequestTest(unittest.TestCase, ResourcesAssocRequest):
    def test_constr(self):
        dot11 = Dot11AssocRequest()
        self.check_empty(dot11)
        eq_(dot11.listen_interval, 0)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.ASSOC_REQ)

    def test_constr_buf(self):
        dot11 = Dot11AssocRequest.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11AssocRequest.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_listen_interval(self):
        dot11 = Dot11AssocRequest()
        dot11.listen_interval = 0x92fd
        eq_(dot11.listen_interval, 0x92fd)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11AssocRequest))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        eq_(Dot11AssocRequest.from_buffer(self.expected_packet).serialize(), self.expected_packet)


class ResourcesAssocResponse(ResourcesManagement):
    expected_packet = _f([17, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 21, 32, 243, 146, 58, 242])

    def check_equals(self, dot1, dot2):
        self.check_capinfo_equals(dot1.capabilities, dot2.capabilities)
        eq_(dot1.status_code, dot2.status_code)
        eq_(dot1.aid, dot2.aid)
        super(ResourcesAssocResponse, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        super(ResourcesAssocResponse, self).check_equals_expected(dot11)
        eq_(dot11.status_code, 0x92f3)
        eq_(dot11.aid, 0xf23a)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.ASSOC_RESP)

class Dot11AssocResponseTest(unittest.TestCase, ResourcesAssocResponse):
    def test_constr(self):
        dot11 = Dot11AssocResponse()
        self.check_empty(dot11)
        eq_(dot11.status_code, 0)
        eq_(dot11.aid, 0)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.ASSOC_RESP)

    def test_constr_buf(self):
        self.check_equals_expected(Dot11AssocResponse.from_buffer(self.expected_packet))

    def test_copy(self):
        dot1 = Dot11AssocResponse.from_buffer(self.expected_packet)
        self.check_equals(dot1, dot1.copy())

    def test_status_code(self):
        dot11 = Dot11AssocResponse()
        dot11.status_code = 0x92f3
        eq_(dot11.status_code, 0x92f3)

    def test_aid(self):
        dot11 = Dot11AssocResponse()
        dot11.aid = 0x92f3
        eq_(dot11.aid, 0x92f3)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11AssocResponse))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        eq_(self.expected_packet, Dot11AssocResponse.from_buffer(self.expected_packet).serialize())

class ResourcesReAssocRequest(ResourcesManagement):
    expected_packet = _f([33, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 21, 32, 243, 146, 3, 4, 5, 6, 7, 8])

    def check_equals(self, dot1, dot2):
        self.check_capinfo_equals(dot1.capabilities, dot2.capabilities)
        eq_(dot1.listen_interval, dot2.listen_interval)
        eq_(dot1.current_ap, dot2.current_ap)
        super(ResourcesReAssocRequest, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        eq_(dot11.listen_interval, 0x92f3)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.REASSOC_REQ)
        super(ResourcesReAssocRequest, self).check_equals_expected(dot11)

class Dot11ReAssocRequestTest(unittest.TestCase, ResourcesReAssocRequest):
    def test_constr(self):
        dot11 = Dot11ReAssocRequest()
        self.check_empty(dot11)
        eq_(dot11.listen_interval, 0)
        eq_(dot11.current_ap, HWAddress())
        eq_(dot11.subtype, Dot11.ManagementSubtypes.REASSOC_REQ)

    def test_constr_buf(self):
        dot11 = Dot11ReAssocRequest.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11ReAssocRequest.from_buffer(self.expected_packet)
        dot2 = dot1.copy()
        self.check_equals(dot1, dot2)

    def test_listen_interval(self):
        dot11 = Dot11ReAssocRequest()
        dot11.listen_interval = 0x92fd
        eq_(dot11.listen_interval, 0x92fd)

    def test_current_ap(self):
        dot11 = Dot11ReAssocRequest()
        dot11.current_ap = "00:01:02:03:04:05"
        eq_(dot11.current_ap, "00:01:02:03:04:05")

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11ReAssocRequest))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        eq_(Dot11ReAssocRequest.from_buffer(self.expected_packet).serialize(), self.expected_packet)


class ResourcesReAssocResponse(ResourcesManagement):
    expected_packet = _f([49, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 21, 32, 243, 146, 58, 242])

    def check_equals(self, dot1, dot2):
        self.check_capinfo_equals(dot1.capabilities, dot2.capabilities)
        eq_(dot1.status_code, dot2.status_code)
        eq_(dot1.aid, dot2.aid)
        super(ResourcesReAssocResponse, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        super(ResourcesReAssocResponse, self).check_equals_expected(dot11)
        eq_(dot11.status_code, 0x92f3)
        eq_(dot11.aid, 0xf23a)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.REASSOC_RESP)


class Dot11ReAssocResponseTest(unittest.TestCase, ResourcesReAssocResponse):
    def test_constr(self):
        dot11 = Dot11ReAssocResponse()
        self.check_empty(dot11)
        eq_(dot11.status_code, 0)
        eq_(dot11.aid, 0)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.REASSOC_RESP)

    def test_constr_buf(self):
        self.check_equals_expected(Dot11ReAssocResponse.from_buffer(self.expected_packet))

    def test_copy(self):
        dot1 = Dot11ReAssocResponse.from_buffer(self.expected_packet)
        self.check_equals(dot1, dot1.copy())

    def test_status_code(self):
        dot11 = Dot11ReAssocResponse()
        dot11.status_code = 0x92f3
        eq_(dot11.status_code, 0x92f3)

    def test_aid(self):
        dot11 = Dot11ReAssocResponse()
        dot11.aid = 0x92f3
        eq_(dot11.aid, 0x92f3)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11ReAssocResponse))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        eq_(self.expected_packet, Dot11ReAssocResponse.from_buffer(self.expected_packet).serialize())

class ResourcesProbeRequest(ResourcesManagement):
    expected_packet = _f([65, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0])

    def check_equals_expected(self, dot11):
        eq_(dot11.subtype, Dot11.ManagementSubtypes.PROBE_REQ)
        super(ResourcesProbeRequest, self).check_equals_expected(dot11)

class Dot11ProbeRequestTest(unittest.TestCase, ResourcesProbeRequest):
    def test_constr(self):
        dot11 = Dot11ProbeRequest()
        self.check_empty(dot11)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.PROBE_REQ)

    def test_constr_buf(self):
        dot11 = Dot11ProbeRequest.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11ProbeRequest.from_buffer(self.expected_packet)
        self.check_equals(dot1, dot1.copy())

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11ProbeRequest))
        self.check_equals_expected(dot11)

class ResourcesProbeResponse(ResourcesManagement):
    expected_packet = _f([81, 1, 79, 35, 0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 7, 0, 0, 145, 138, 131, 39, 223, 152, 166, 23, 141, 146, 0, 0])

    def check_equals(self, dot1, dot2):
        eq_(dot1.interval, dot2.interval)
        eq_(dot1.timestamp, dot2.timestamp)
        super(ResourcesProbeResponse, self).check_equals(dot1, dot2)

    def check_equals_expected(self, dot11):
        super(ResourcesProbeResponse, self).check_equals_expected(dot11)
        eq_(dot11.timestamp, 0x17a698df27838a91)
        eq_(dot11.interval, 0x928d)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.PROBE_RESP)

class Dot11ProbeResponseTest(unittest.TestCase, ResourcesProbeResponse):
    def test_constr(self):
        dot11 = Dot11ProbeResponse()
        self.check_empty(dot11)
        eq_(dot11.timestamp, 0)
        eq_(dot11.interval, 0)
        eq_(dot11.subtype, Dot11.ManagementSubtypes.PROBE_RESP)

    def test_constr_buf(self):
        dot11 = Dot11ProbeResponse.from_buffer(self.expected_packet)
        self.check_equals_expected(dot11)

    def test_copy(self):
        dot1 = Dot11ProbeResponse.from_buffer(self.expected_packet)
        self.check_equals(dot1, dot1.copy())

    def test_interval(self):
        dot11 = Dot11ProbeResponse()
        dot11.interval = 0x92af
        eq_(dot11.interval, 0x92af)

    def test_timestamp(self):
        dot11 = Dot11ProbeResponse()
        dot11.timestamp = 0x92af8a72df928a7c
        eq_(dot11.timestamp, 0x92af8a72df928a7c)

    def test_from_bytes(self):
        dot11 = Dot11.from_bytes(self.expected_packet)
        ok_(isinstance(dot11, Dot11ProbeResponse))
        self.check_equals_expected(dot11)

    def test_serialize(self):
        eq_(self.expected_packet, Dot11ProbeResponse.from_buffer(self.expected_packet).serialize())
