# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_, eq_, assert_equal, assert_false, assert_true, assert_raises
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PPPoE, UDP, ICMP, OptionNotFound, DNS, DHCP, IPv4Address

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"


def _f(packet):
    return "".join(chr(i) for i in packet)

expected_packet = [
    17, 9, 0, 0, 0, 16, 1, 1, 0, 0, 1, 2, 0, 0, 1, 3, 0, 4, 97, 98, 99, 100
]

session_packet = [
    17, 0, 0, 98, 0, 21, 192, 33, 1, 11, 0, 19, 1, 4, 5, 212, 3, 5,
    194, 35, 5, 5, 6, 22, 173, 224, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0
]

full_session_packet = [
    0, 5, 133, 192, 164, 17, 0, 144, 26, 65, 118, 126, 136, 100, 17,
    0, 0, 98, 0, 21, 192, 33, 1, 11, 0, 19, 1, 4, 5, 212, 3, 5, 194,
    35, 5, 5, 6, 22, 173, 224, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0
]

expected_packet, session_packet, full_session_packet = _f(expected_packet), _f(session_packet), _f(full_session_packet)

class PPPoETest(unittest.TestCase):
    def test_default_constructor(self):
        pdu = PPPoE()
        eq_(pdu.version, 1)
        eq_(pdu.type, 1)
        eq_(pdu.code, 0)
        eq_(pdu.session_id, 0)
        eq_(pdu.payload_length, 0)

    def test_constr_buf(self):
        pdu = PPPoE.from_buffer(session_packet)
        eq_(pdu.version, 1)
        eq_(pdu.type, 1)
        eq_(pdu.code, 0x00)
        eq_(pdu.session_id, 0x62)
        eq_(pdu.payload_length, 21)
        eq_(len(pdu.tags), 0)

        raw = pdu.rfind_pdu(RAW)
        eq_(raw.payload_size, 21)

    def test_constr_full_session_buf(self):
        eth = EthernetII.from_buffer(full_session_packet)
        pdu = eth.rfind_pdu(PPPoE)
        eq_(pdu.version, 1)
        eq_(pdu.type, 1)
        eq_(pdu.code, 0x00)
        eq_(pdu.session_id, 0x62)
        eq_(pdu.payload_length, 21)
        eq_(len(pdu.tags), 0)
        raw = pdu.rfind_pdu(RAW)
        eq_(raw.payload_size, 21)

    def test_constr_buf2(self):
        pdu = PPPoE.from_buffer(expected_packet)
        eq_(pdu.version, 1)
        eq_(pdu.type, 1)
        eq_(pdu.code, 0x09)
        eq_(pdu.session_id, 0)
        eq_(pdu.payload_length, 16)
        eq_(len(pdu.tags), 3)
        eq_(pdu.service_name, "")
        pdu.search_tag(PPPoE.TagTypes.SERVICE_NAME)

    def test_stacked_eth(self):
        eth = EthernetII() / PPPoE()
        buf = eth.serialize()
        eth2 = EthernetII.from_buffer(buf)
        assert_true(eth2.rfind_pdu(PPPoE) is not None)

    def test_stacked_eth_with_tags(self):
        pdu = PPPoE.from_buffer(expected_packet)
        eth = EthernetII() / pdu
        buf = eth.serialize()
        eth2 = EthernetII.from_buffer(buf)
        unserial = eth2.rfind_pdu(PPPoE)
        eq_(expected_packet, unserial.serialize())

    def test_serialize(self):
        pdu = PPPoE.from_buffer(expected_packet)
        buf = pdu.serialize()
        eq_(expected_packet, buf)

    def test_version(self):
        pdu = PPPoE()
        pdu.version = 6
        eq_(pdu.version, 6)

    def test_type(self):
        pdu = PPPoE()
        pdu.type = 6
        eq_(pdu.type, 6)

    def test_code(self):
        pdu = PPPoE()
        pdu.code = 0x7a
        eq_(pdu.code, 0x7a)

    def test_session_id(self):
        pdu = PPPoE()
        pdu.session_id = 0x9182
        eq_(pdu.session_id, 0x9182)

    def test_payload_len(self):
        pdu = PPPoE()
        pdu.payload_length = 0x9182
        eq_(pdu.payload_length, 0x9182)

    def test_service_name(self):
        pdu = PPPoE()
        pdu.service_name = "carlos"
        eq_(pdu.service_name, "carlos")

    def test_acname(self):
        pdu = PPPoE()
        pdu.ac_name = "carlos"
        eq_(pdu.ac_name, "carlos")

    def test_host_uniq(self):
        pdu = PPPoE()
        pdu.host_uniq = _f([1, 2, 3, 4, 5, 6])
        eq_(pdu.host_uniq, _f([1, 2, 3, 4, 5, 6]))

    def test_accookie(self):
        pdu = PPPoE()
        pdu.ac_cookie = _f([1, 2, 3, 4, 5, 6])
        eq_(pdu.ac_cookie, _f([1, 2, 3, 4, 5, 6]))

    def test_vendor(self):
        pdu = PPPoE()
        pdu.set_vendor_specific(0x9283f78, _f([1, 2, 3, 4, 5, 6]))
        vendor_id, data = pdu.get_vendor_specific()
        eq_(vendor_id, 0x9283f78)
        eq_(data, _f([1, 2, 3, 4, 5, 6]))

    def test_relay_sessionid(self):
        pdu = PPPoE()
        pdu.relay_session_id = _f([1, 2, 3, 4, 5, 6])
        eq_(pdu.relay_session_id, _f([1, 2, 3, 4, 5, 6]))

    def test_sname_error(self):
        pdu = PPPoE()
        pdu.service_name_error = "carlos"
        eq_(pdu.service_name_error, "carlos")
        pdu = PPPoE()
        pdu.service_name_error = b""
        eq_(pdu.service_name_error, b"")

    def test_acsystem_error(self):
        pdu = PPPoE()
        pdu.ac_system_error = "carlos"
        eq_(pdu.ac_system_error, "carlos")

    def test_generic_error(self):
        pdu = PPPoE()
        pdu.generic_error = "carlos"
        eq_(pdu.generic_error, "carlos")

