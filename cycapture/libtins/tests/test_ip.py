# -*- coding: utf-8 -*-

import unittest
from nose.tools import ok_
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"


def _f(packet):
    return "".join(chr(i) for i in packet)


def chk_equals(obj, ip1, ip2):
    obj.assertEquals(ip1.src_addr, ip2.src_addr)
    obj.assertEquals(ip1.dst_addr, ip2.dst_addr)
    obj.assertEquals(ip1.id, ip2.id)
    obj.assertEquals(ip1.frag_off, ip2.frag_off)
    obj.assertEquals(ip1.tos, ip2.tos)
    obj.assertEquals(ip1.ttl, ip2.ttl)
    obj.assertEquals(ip1.version, ip2.version)
    obj.assertEquals(ip1.ref_inner_pdu() is None, ip2.ref_inner_pdu() is None)


expected_packet = _f([
    40, 127, 0, 32, 0, 122, 0, 67, 21, 1, 0, 0, 84, 52, 254, 5, 192,
    168, 9, 43, 130, 11, 116, 106, 103, 171, 119, 171, 104, 101, 108, 0
])

fragmented_packet = _f([
    69, 0, 0, 60, 0, 242, 7, 223, 64, 17, 237, 220, 192, 0, 2, 1, 192,
    0, 2, 2, 192, 0, 192, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
])

fragmented_ether_ip_packet = _f([
    0, 10, 94, 83, 216, 229, 0, 21, 197, 50, 245, 6, 8, 0, 69, 0, 0, 60,
    0, 242, 7, 223, 64, 17, 237, 220, 192, 0, 2, 1, 192, 0, 2, 2, 192, 0,
    192, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
])

tot_len_zero_packet = _f([
    60, 151, 14, 219, 60, 164, 60, 151, 14, 218, 161, 43, 8, 0, 69, 0
    , 0, 0, 29, 214, 64, 0, 128, 6, 0, 0, 192, 168, 1, 20, 192, 168,
    1, 21, 192, 190, 23, 172, 226, 151, 206, 49, 83, 30, 140, 232, 80
    , 24, 1, 0, 131, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 165, 111, 64, 0, 1, 0, 0, 0, 2, 66, 65, 0, 2
    , 66, 65, 0, 0, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32,
    0, 32, 0, 32, 0, 40, 0, 40, 0, 40, 0, 40, 0, 40, 0, 32, 0, 32, 0,
    32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0,
    32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 32, 0, 72, 0, 16, 0, 16
    , 0, 16, 0, 16, 0, 16, 0, 16, 0, 16, 0, 16, 0, 16, 0, 16, 0, 16,
    0, 16, 0, 16, 0, 16, 0, 16, 0, 132, 0, 132, 0, 132, 0, 132, 0,
    132, 0, 132, 0, 132, 0, 132, 0, 132, 0, 132, 0, 16, 0, 16, 0, 16,
    0, 16, 0, 16, 0, 16, 0, 16, 0, 129, 0, 129, 0, 129, 0, 129, 0,
    129, 0, 129, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1
    , 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
    1, 0, 16, 0, 16, 0, 16, 0, 16, 0, 16, 0, 16, 0, 130, 0, 130, 0,
    130, 0, 130, 0, 130, 0, 130, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2,
    0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2,
    0, 2, 0, 2, 0, 2, 0, 16, 0, 16, 0, 16, 0, 16, 0, 32, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 46
    , 0, 0, 0, 1, 0, 0, 0, 120, 16, 65, 0, 104, 16, 65, 0, 255, 255,
    255, 255, 0, 10, 0, 0, 16, 0, 0, 0, 248, 3, 0, 0, 32, 5, 147, 25,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 192, 11, 0, 0, 0, 0
    , 0, 0, 0, 29, 0, 0, 192, 4, 0, 0, 0, 0, 0, 0, 0, 150, 0, 0, 192,
    4, 0, 0, 0, 0, 0, 0, 0, 141, 0, 0, 192, 8, 0, 0, 0, 0, 0, 0, 0,
    142, 0, 0, 192, 8, 0, 0, 0, 0, 0, 0, 0, 143, 0, 0, 192, 8, 0, 0,
    0, 0, 0, 0, 0, 144, 0, 0, 192, 8, 0, 0, 0, 0, 0, 0, 0, 145, 0, 0,
    192, 8, 0, 0, 0, 0, 0, 0, 0, 146, 0, 0, 192, 8, 0, 0, 0, 0, 0, 0
    , 0, 147, 0, 0, 192, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 7, 0, 0,
    0, 10, 0, 0, 0, 140, 0, 0, 0, 2, 0, 0, 0, 240, 18, 65, 0, 8, 0,
    0, 0, 196, 18, 65, 0, 9, 0, 0, 0, 152, 18, 65, 0, 10, 0, 0, 0,
    116, 18, 65, 0, 16, 0, 0, 0, 72, 18, 65, 0, 17, 0, 0, 0, 24, 18,
    65, 0, 18, 0, 0, 0, 244, 17, 65, 0, 19, 0, 0, 0, 200, 17, 65, 0,
    24, 0, 0, 0, 144, 17, 65, 0, 25, 0, 0, 0, 104, 17, 65, 0, 26, 0,
    0, 0, 48, 17, 65, 0, 27, 0, 0, 0, 248, 16, 65, 0, 28, 0, 0, 0,
    208, 16, 65, 0, 120, 0, 0, 0, 192, 16, 65, 0, 121, 0, 0, 0, 176,
    16, 65, 0, 122, 0, 0, 0, 160, 16, 65, 0, 252, 0, 0, 0, 156, 16,
    65, 0, 255, 0, 0, 0, 140, 16, 65, 0, 15, 197, 64, 0, 15, 197, 64,
    0, 15, 197, 64, 0, 15, 197, 64, 0, 15, 197, 64, 0, 15, 197, 64,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 8, 0, 0, 0, 0, 164, 3, 0, 0,
    96, 130, 121, 130, 33, 0, 0, 0, 0, 0, 0, 0, 166, 223, 0, 0, 0, 0,
    0, 0, 161, 165, 0, 0, 0, 0, 0, 0, 129, 159, 224, 252, 0, 0, 0, 0
    , 64, 126, 128, 252, 0, 0, 0, 0, 168, 3, 0, 0, 193, 163, 218, 163
    , 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 129, 254, 0, 0, 0, 0, 0, 0, 64, 254, 0, 0, 0, 0, 0, 0,
    181, 3, 0, 0, 193, 163, 218, 163, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 254, 0, 0, 0, 0, 0
    , 0, 65, 254, 0, 0, 0, 0, 0, 0, 182, 3, 0, 0, 207, 162, 228, 162,
    26, 0, 229, 162, 232, 162, 91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 129, 254, 0, 0, 0, 0, 0, 0, 64, 126, 161, 254,
    0, 0, 0, 0, 81, 5, 0, 0, 81, 218, 94, 218, 32, 0, 95, 218, 106,
    218, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129,
    211, 216, 222, 224, 249, 0, 0, 49, 126, 129, 254, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 22, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0
    , 0, 3, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 24, 0, 0, 0, 5, 0, 0, 0,
    13, 0, 0, 0, 6, 0, 0, 0, 9, 0, 0, 0, 7, 0, 0, 0, 12, 0, 0, 0, 8,
    0, 0, 0, 12, 0, 0, 0, 9, 0, 0, 0, 12, 0, 0, 0, 10, 0, 0, 0, 7, 0
    , 0, 0, 11, 0, 0, 0, 8, 0, 0, 0, 12, 0, 0, 0, 22, 0, 0, 0, 13, 0,
    0, 0, 22, 0, 0, 0, 15, 0, 0, 0, 2, 0, 0, 0, 16, 0, 0, 0, 13, 0,
    0, 0, 17, 0, 0, 0, 18, 0, 0, 0, 18, 0, 0, 0, 2, 0, 0, 0, 33, 0, 0
    , 0, 13, 0, 0, 0, 53, 0, 0, 0, 2, 0, 0, 0, 65, 0, 0, 0, 13, 0, 0,
    0, 67, 0, 0, 0, 2, 0, 0, 0, 80, 0, 0, 0, 17, 0, 0, 0, 82, 0, 0,
    0, 13, 0, 0, 0, 83, 0, 0, 0, 13, 0, 0, 0, 87, 0, 0, 0, 22, 0, 0,
    0, 89, 0, 0, 0, 11, 0, 0, 0, 108, 0, 0, 0, 13, 0, 0, 0, 109, 0, 0
    , 0, 32, 0, 0, 0, 112, 0, 0, 0, 28, 0, 0, 0, 114, 0, 0, 0, 9, 0,
    0, 0, 6, 0, 0, 0, 22, 0, 0, 0, 128, 0, 0, 0, 10, 0, 0, 0, 129, 0,
    0, 0, 10, 0, 0, 0, 130, 0, 0, 0, 9, 0, 0, 0, 131, 0, 0, 0, 22, 0
    , 0, 0, 132, 0, 0, 0, 13, 0, 0, 0, 145, 0, 0, 0, 41, 0, 0, 0, 158
    , 0, 0, 0, 13, 0, 0, 0, 161, 0, 0, 0, 2, 0, 0, 0, 164, 0, 0, 0,
    11, 0, 0, 0, 167, 0, 0, 0, 13, 0, 0, 0, 183, 0, 0, 0, 17, 0, 0, 0
    , 206, 0, 0, 0, 2, 0, 0, 0, 215, 0, 0, 0, 11, 0, 0, 0, 24, 7, 0,
    0, 12, 0, 0, 0, 128, 112, 0, 0, 1, 0, 0, 0, 240, 241, 255, 255,
    80, 83, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    80, 68, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    228, 71, 65, 0, 36, 72, 65, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0,
    0, 0, 0, 0, 255, 255, 255, 255, 30, 0, 0, 0, 59, 0, 0, 0, 90, 0,
    0, 0, 120, 0, 0, 0, 151, 0, 0, 0, 181, 0, 0, 0, 212, 0, 0, 0,
    243, 0, 0, 0, 17, 1, 0, 0, 48, 1, 0, 0, 78, 1, 0, 0, 109, 1, 0, 0
    , 255, 255, 255, 255, 30, 0, 0, 0, 58, 0, 0, 0, 89, 0, 0, 0, 119,
    0, 0, 0, 150, 0, 0, 0, 180, 0, 0, 0, 211, 0, 0, 0, 242, 0, 0, 0,
    16, 1, 0, 0, 47, 1, 0, 0, 77, 1, 0, 0, 108, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 13, 0, 13, 0, 10, 0, 0, 166, 53,
    0, 47, 0, 63, 0, 0, 149, 0, 164, 71, 0, 224, 71, 224, 71, 224,
    119, 0, 151, 72, 0, 224, 72, 224, 72, 224, 141, 0, 152, 73, 0,
    224, 73, 224, 73, 224, 134, 0, 153, 75, 0, 224, 75, 224, 75, 224,
    115, 0, 155, 77, 0, 224, 77, 224, 77, 224, 116, 0, 157, 79, 0,
    224, 79, 224, 79, 224, 117, 0, 159, 80, 0, 224, 80, 224, 80, 224,
    145, 0, 160, 81, 0, 224, 81, 224, 81, 224, 118, 0, 161, 82, 0,
    224, 82, 224, 82, 224, 146, 0, 162, 83, 0, 224, 83, 224, 83, 224,
    147, 0, 163, 0, 0, 0, 0, 0, 0, 0, 0, 27, 0, 27, 0, 27, 0, 0, 1,
    49, 0, 33, 0, 0, 0, 0, 120, 50, 0, 64, 0, 0, 3, 0, 121, 51, 0, 35
    , 0, 0, 0, 0, 122, 52, 0, 36, 0, 0, 0, 0, 123, 53, 0, 37, 0, 0, 0
    , 0, 124, 54, 0, 94, 0, 30, 0, 0, 125, 55, 0, 38, 0, 0, 0, 0, 126
    , 56, 0, 42, 0, 0, 0, 0, 127, 57, 0, 40, 0, 0, 0, 0, 128, 48, 0,
    41, 0, 0, 0, 0, 129, 45, 0, 95, 0, 31, 0, 0, 130, 61, 0, 43, 0, 0
    , 0, 0, 131, 8, 0, 8, 0, 127, 0, 0, 14, 9, 0, 0, 15, 0, 148, 0,
    15, 113, 0, 81, 0, 17, 0, 0, 16, 119, 0, 87, 0, 23, 0, 0, 17, 101
    , 0, 69, 0, 5, 0, 0, 18, 114, 0, 82, 0, 18, 0, 0, 19, 116, 0, 84,
    0, 20, 0, 0, 20, 121, 0, 89, 0, 25, 0, 0, 21, 117, 0, 85, 0, 21,
    0, 0, 22, 105, 0, 73, 0, 9, 0, 0, 23, 111, 0, 79, 0, 15, 0, 0,
    24, 112, 0, 80, 0, 16, 0, 0, 25, 91, 0, 123, 0, 27, 0, 0, 26, 93,
    0, 125, 0, 29, 0, 0, 27, 13, 0, 13, 0, 10, 0, 0, 28, 0, 0, 0, 0,
    0, 0, 0, 0, 97, 0, 65, 0, 1, 0, 0, 30, 115, 0, 83, 0, 19, 0, 0,
    31, 100, 0, 68, 0, 4, 0, 0, 32, 102, 0, 70, 0, 6, 0, 0, 33, 103,
    0, 71, 0, 7, 0, 0, 34, 104, 0, 72, 0, 8, 0, 0, 35, 106, 0, 74, 0,
    10, 0, 0, 36, 107, 0, 75, 0, 11, 0, 0, 37, 108, 0, 76, 0, 12, 0,
    0, 38, 59, 0, 58, 0, 0, 0, 0, 39, 39, 0, 34, 0, 0, 0, 0, 40, 96,
    0, 126, 0, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0, 92, 0, 124, 0,
    28, 0, 0, 0, 122, 0, 90, 0, 26, 0, 0, 44, 120, 0, 88, 0, 24, 0, 0
    , 45, 99, 0, 67, 0, 3, 0, 0, 46, 118, 0, 86, 0, 22, 0, 0, 47, 98,
    0, 66, 0, 2, 0, 0, 48, 110, 0, 78, 0, 14, 0, 0, 49, 109, 0, 77,
    0, 13, 0, 0, 50, 44, 0, 60, 0, 0, 0, 0, 51, 46, 0, 62, 0, 0, 0, 0
    , 52, 47, 0, 63, 0, 0, 0, 0, 53, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0
    , 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 32, 0, 32, 0,
    32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 59, 0, 84, 0, 94, 0, 104, 0, 60
    , 0, 85, 0, 95, 0, 105, 0, 61, 0, 86, 0, 96, 0, 106, 0, 62, 0, 87
    , 0, 97, 0, 107, 0, 63, 0, 88, 0, 98, 0, 108, 0, 64, 0, 89, 0, 99
    , 0, 109, 0, 65, 0, 90, 0, 100, 0, 110, 0, 66, 0, 91, 0, 101, 0,
    111, 0, 67, 0, 92, 0, 102, 0, 112, 0, 68, 0, 93, 0, 103, 0, 113,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 55, 0, 0,
    119, 0, 0, 0, 72, 56, 0, 0, 141, 0, 0, 0, 73, 57, 0, 0, 132, 0, 0
    , 0, 0, 45, 0, 0, 0, 0, 0, 0, 75, 52, 0, 0, 115, 0, 0, 0, 0, 53,
    0, 0, 0, 0, 0, 0, 77, 54, 0, 0, 116, 0, 0, 0, 0, 43, 0, 0, 0, 0,
    0, 0, 79, 49, 0, 0, 117, 0, 0, 0, 80, 50, 0, 0, 145, 0, 0, 0, 81,
    51, 0, 0, 118, 0, 0, 0, 82, 48, 0, 0, 146, 0, 0, 0, 83, 46, 0, 0
    , 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 224, 133, 224, 135, 224, 137, 224, 139, 224,
    134, 224, 136, 224, 138, 224, 140, 255, 255, 255, 255, 254, 255,
    255, 255, 254, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    , 0, 0, 0, 0, 0
])

class IPTest(unittest.TestCase):
    def test_default_constructor(self):
        ip = IP()
        self.assertEquals(str(ip.dst_addr), "0.0.0.0")
        self.assertEquals(str(ip.src_addr), "0.0.0.0")
        self.assertEquals(ip.version, 4)
        self.assertEquals(ip.id, 1)
        self.assertEquals(ip.pdu_type, PDU.IP)

    def test_copy(self):
        ip1 = IP.from_buffer(expected_packet)
        ip2 = ip1.copy()
        chk_equals(self, ip1, ip2)

    def test_nested_copy(self):
        nested = IP.from_buffer(expected_packet)
        ip1 = IP()
        ip1.set_inner_pdu(nested)
        ip2 = ip1.copy()
        chk_equals(self, ip1, ip2)

    def test_constructor(self):
        ip = IP("192.168.0.1", "192.168.0.100")
        self.assertEquals(str(ip.dst_addr), "192.168.0.1")
        self.assertEquals(str(ip.src_addr), "192.168.0.100")
        self.assertEquals(ip.version, 4)
        self.assertEquals(ip.id, 1)

    def test_construct_fragmented_packet(self):
        ip = IP.from_buffer(fragmented_packet)
        self.assertTrue(ip.ref_inner_pdu() is not None)
        self.assertEquals(ip.ref_inner_pdu().pdu_type, PDU.RAW)

    def test_serialize_fragmented(self):
        pkt = EthernetII.from_buffer(fragmented_ether_ip_packet)
        buf = pkt.serialize()
        self.assertEquals(fragmented_ether_ip_packet, buf)

    def test_total_length_zero_packet(self):
        pkt = EthernetII.from_buffer(tot_len_zero_packet)
        self.assertTrue(pkt.rfind_pdu(TCP) is not None)
        self.assertTrue(pkt.rfind_pdu(RAW) is not None)
        self.assertEquals(8192, pkt.rfind_pdu(RAW).payload_size)

    def test_tos(self):
        ip = IP()
        ip.tos = 0x7a
        self.assertEquals(ip.tos, 0x7a)

    def test_id(self):
        ip = IP()
        ip.id = 0x7f1a
        self.assertEquals(ip.id, 0x7f1a)

    def test_frag_off(self):
        ip = IP()
        ip.frag_off = 0x7f1a
        self.assertEquals(ip.frag_off, 0x7f1a)

    def test_ttl(self):
        ip = IP()
        ip.ttl = 0x7f
        self.assertEquals(ip.ttl, 0x7f)

    def test_protocol(self):
        ip = IP()
        ip.protocol = 0x7f
        self.assertEquals(ip.protocol, 0x7f)

    def test_src_ip_string(self):
        ip = IP()
        ip.src_addr = "192.155.32.10"
        self.assertEquals(ip.src_addr, "192.155.32.10")

    def test_dst_ip_string(self):
        ip = IP()
        ip.dst_addr = "192.155.32.10"
        self.assertEquals(ip.dst_addr, "192.155.32.10")

    def test_version(self):
        ip = IP()
        ip.version = 0xb
        self.assertEquals(ip.version, 0xb)

    def test_sec_option(self):
        ip = IP()
        sec_t = IP.SecurityType(0x746a, 26539, 0x77ab, 0x68656c)
        ip.set_security(sec_t)
        found = ip.get_security()
        self.assertEquals(found.security, 0x746a)
        self.assertEquals(found.compartments, 26539)
        self.assertEquals(found.handling_restrictions, 0x77ab)
        self.assertEquals(found.transmission_control, 0x68656c)

    def test_lsrr_option(self):
        ip = IP()
        ip.set_lsrr(0x2d, ["192.168.2.3", "192.168.5.1"])
        pointer, routes = ip.get_lsrr()
        self.assertEquals(pointer, 0x2d)
        self.assertEquals(routes, ["192.168.2.3", "192.168.5.1"])

    def test_ssrr_option(self):
        ip = IP()
        ip.set_ssrr(0x2d, ["192.168.2.3", "192.168.5.1"])
        pointer, routes = ip.get_ssrr()
        self.assertEquals(pointer, 0x2d)
        self.assertEquals(routes, ["192.168.2.3", "192.168.5.1"])

    def test_record_route_option(self):
        ip = IP()
        ip.set_record_route(0x2d, ["192.168.2.3", "192.168.5.1"])
        pointer, routes = ip.get_record_route()
        self.assertEquals(pointer, 0x2d)
        self.assertEquals(routes, ["192.168.2.3", "192.168.5.1"])

    def test_stream_id(self):
        ip = IP()
        ip.stream_identifier = 0x91fa
        self.assertEquals(ip.stream_identifier, 0x91fa)

    def test_add_option(self):
        ip = IP()

        data = _f([0x15, 0x17, 0x94, 0x66, 0xff])
        ident = IP.OptionIdentifier(IP.OptionNumber.SEC, IP.OptionClass.CONTROL, 1)
        ip.add_option(ident, data)
        returned_data = ip.search_option(ident)
        self.assertEquals(returned_data, data)

        ident = IP.OptionIdentifier(IP.OptionNumber.SSRR, IP.OptionClass.CONTROL, 1)
        ok_(ip.search_option(ident) is None)

    def test_constructor_from_buffer(self):
        ip = IP.from_buffer(expected_packet)
        self.assertEquals(ip.src_addr, "84.52.254.5")
        self.assertEquals(ip.dst_addr, "192.168.9.43")
        self.assertEquals(ip.id, 0x7a)
        self.assertEquals(ip.tos, 0x7f)
        self.assertEquals(ip.frag_off, 0x43)
        self.assertEquals(ip.protocol, 1)
        self.assertEquals(ip.ttl, 0x15)
        self.assertEquals(ip.version, 2)

    def test_serialize(self):
        ip1 = IP.from_buffer(expected_packet)
        buf = ip1.serialize()
        if IS_MACOSX:
            # todo: add workaround for BSD too
            buf = bytearray(buf)
            buf[2], buf[3] = buf[3], buf[2]
            buf = bytes(buf)
        self.assertEquals(expected_packet, buf)

    def test_stacked_protocols(self):

        ip = IP() / TCP()
        ip.dst_addr = "127.0.0.1"
        ip.src_addr = "127.0.0.1"
        buf = ip.serialize()
        ip2 = IP.from_buffer(buf)
        self.assertTrue(ip2.rfind_pdu(TCP) is not None)

        ip = IP() / UDP()
        ip.dst_addr = "127.0.0.1"
        ip.src_addr = "127.0.0.1"
        buf = ip.serialize()
        ip2 = IP.from_buffer(buf)
        self.assertTrue(ip2.rfind_pdu(UDP) is not None)

        ip = IP() / ICMP()
        ip.dst_addr = "127.0.0.1"
        ip.src_addr = "127.0.0.1"
        buf = ip.serialize()
        ip2 = IP.from_buffer(buf)
        self.assertTrue(ip2.rfind_pdu(ICMP) is not None)



# TEST_F(IPTest, SpoofedOptions) {
#     IP pdu;
#     uint8_t a[] = { 1,2,3,4,5,6 };
#     pdu.add_option(
#         IP::option(IP::NOOP, 250, a, a + sizeof(a))
#     );
#     pdu.add_option(
#         IP::option(IP::NOOP, 250, a, a + sizeof(a))
#     );
#     pdu.add_option(
#         IP::option(IP::NOOP, 250, a, a + sizeof(a))
#     );
#     // probably we'd expect it to crash if it's not working, valgrind plx
#     EXPECT_EQ(3U, pdu.options().size());
#     EXPECT_EQ(pdu.serialize().size(), pdu.size());
# }
