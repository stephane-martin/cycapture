# -*- coding: utf-8 -*-

import unittest
# noinspection PyUnresolvedReferences
from .._tins import EthernetII, HWAddress, PDU, IP, TCP, RAW, PDUNotFound, UDP, ICMP, OptionNotFound, DNS
# noinspection PyUnresolvedReferences
from .._tins import DNS_Query, DNS_Resource

import platform
IS_MACOSX = platform.system().lower().strip() == "darwin"

def _f(packet):
    return "".join(chr(i) for i in packet)

def check_equals(obj, dns1, dns2):
    obj.assertEquals(dns1.id, dns2.id)
    obj.assertEquals(dns1.qrtype, dns2.qrtype)
    obj.assertEquals(dns1.opcode, dns2.opcode)
    obj.assertEquals(dns1.authoritative_answer, dns2.authoritative_answer)
    obj.assertEquals(dns1.truncated, dns2.truncated)
    obj.assertEquals(dns1.recursion_desired, dns2.recursion_desired)
    obj.assertEquals(dns1.recursion_available, dns2.recursion_available)
    obj.assertEquals(dns1.z, dns2.z)
    obj.assertEquals(dns1.authenticated_data, dns2.authenticated_data)
    obj.assertEquals(dns1.checking_disabled, dns2.checking_disabled)
    obj.assertEquals(dns1.rcode, dns2.rcode)
    obj.assertEquals(dns1.questions_count(), dns2.questions_count())
    obj.assertEquals(dns1.answers_count(), dns2.answers_count())
    obj.assertEquals(dns1.authority_count(), dns2.authority_count())
    obj.assertEquals(dns1.additional_count(), dns2.additional_count())
    obj.assertEquals(dns1.pdu_type, dns2.pdu_type)
    obj.assertEquals(dns1.header_size, dns2.header_size)
    obj.assertEquals(dns1.ref_inner_pdu() is None, dns2.ref_inner_pdu() is None)


expected_packet = _f([
    0, 19, 215, 154, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101,
    120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 3, 119,
    119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0,
    0, 1, 0, 1, 0, 0, 18, 52, 0, 4, 192, 168, 0, 1
])

dns_response1 = _f([
    174, 73, 129, 128, 0, 1, 0, 5, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 15, 0, 1, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 17, 0, 50, 4, 97, 108, 116, 52, 5, 97, 115, 112, 109, 120, 1, 108, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 9, 0, 40, 4, 97, 108, 116, 51, 192, 47, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 9, 0, 20, 4, 97, 108, 116, 49, 192, 47, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 4, 0, 10, 192, 47, 192, 12, 0, 15, 0, 1, 0, 0, 2, 88, 0, 9, 0, 30, 4, 97, 108, 116, 50, 192, 47
])


class DNSTest(unittest.TestCase):

    def test_constr(self):
        dns = DNS.from_buffer(expected_packet)
        self.assertEquals(dns.id, 0x13)
        self.assertEquals(dns.qrtype, DNS.QRType.RESPONSE)
        self.assertEquals(dns.opcode, 0xa)
        self.assertEquals(dns.authoritative_answer, 1)
        self.assertEquals(dns.truncated, 1)
        self.assertEquals(dns.recursion_desired, 1)
        self.assertEquals(dns.recursion_available, 1)
        self.assertEquals(dns.z, 0)
        self.assertEquals(dns.rcode, 0xa)
        self.assertEquals(dns.questions_count(), 1)
        self.assertEquals(dns.answers_count(), 1)

        queries = dns.get_queries()
        self.assertEquals(len(queries), 1)
        self.assertEquals(queries[0], DNS_Query("www.example.com", DNS.QueryType.A, DNS.QueryClass.IN))

        answers = dns.get_answers()
        self.assertEquals(len(answers), 1)
        self.assertEquals(answers[0], DNS_Resource("www.example.com", "192.168.0.1", DNS.QueryType.A, DNS.QueryClass.IN, 0x1234))

    def test_constr2(self):
        dns = DNS.from_buffer(dns_response1)
        self.assertEquals(dns.questions_count(), 1)
        self.assertEquals(dns.answers_count(), 5)

        def check(dns):
            for q in dns.get_queries():
                self.assertEquals(q.name, "google.com")
                self.assertTrue(q.query_type in [DNS.QueryType.MX, DNS.QueryType.A])
                self.assertEquals(q.query_class, DNS.QueryClass.IN)
            for a in dns.get_answers():
                self.assertEquals(a.name, "google.com")
                self.assertEquals(a.query_type, DNS.QueryType.MX)
                self.assertEquals(a.query_class, DNS.QueryClass.IN)
                self.assertTrue(a.data in [
                    "alt1.aspmx.l.google.com",
                    "alt2.aspmx.l.google.com",
                    "alt3.aspmx.l.google.com",
                    "alt4.aspmx.l.google.com",
                    "alt5.aspmx.l.google.com",
                    "aspmx.l.google.com"
                ])

        check(dns)
        dns.add_query(DNS.Query("google.com", DNS.QueryType.A, DNS.QueryClass.IN))
        dns.add_query(DNS.Query("google.com", DNS.QueryType.MX, DNS.QueryClass.IN))
        dns.add_answer(DNS.Resource("google.com", "alt5.aspmx.l.google.com", DNS.QueryType.MX, DNS.QueryClass.IN, 0x762))
        check(dns)

    def test_serialization(self):
        dns = DNS.from_buffer(expected_packet)
        buf = dns.serialize()
        self.assertEquals(expected_packet, buf)

    def test_copy(self):
        dns = DNS.from_buffer(expected_packet)
        dns2 = dns.copy()
        check_equals(self, dns, dns2)

    def test_nested(self):
        nested = DNS.from_buffer(expected_packet)
        dns1 = DNS.from_buffer(expected_packet)
        dns1.set_inner_pdu(nested)
        dns2 = dns1.copy()
        check_equals(self, dns1, dns2)

    def test_id(self):
        dns = DNS()
        dns.id = 0x7263
        self.assertEquals(dns.id, 0x7263)

    def test_qrtype(self):
        dns = DNS()
        dns.qrtype = DNS.QRType.RESPONSE
        self.assertEquals(dns.qrtype, DNS.QRType.RESPONSE)

    def test_opcode(self):
        dns = DNS()
        dns.opcode = 0xa
        self.assertEquals(dns.opcode, 0xa)

    def test_auth_answer(self):
        dns = DNS()
        dns.authoritative_answer = 1
        self.assertEquals(dns.authoritative_answer, 1)

    def test_truncated(self):
        dns = DNS()
        dns.truncated = 1
        self.assertEquals(dns.truncated, 1)

    def test_recursion_d(self):
        dns = DNS()
        dns.recursion_desired = 1
        self.assertEquals(dns.recursion_desired, 1)

    def test_recursion_a(self):
        dns = DNS()
        dns.recursion_available = 1
        self.assertEquals(dns.recursion_available, 1)

    def test_z(self):
        dns = DNS()
        dns.z = 1
        self.assertEquals(dns.z, 1)

    def test_auth_data(self):
        dns = DNS()
        dns.authenticated_data = 1
        self.assertEquals(dns.authenticated_data, 1)

    def test_check_disabled(self):
        dns = DNS()
        dns.checking_disabled = 1
        self.assertEquals(dns.checking_disabled, 1)

    def test_rcode(self):
        dns = DNS()
        dns.rcode = 0xa
        self.assertEquals(dns.rcode, 0xa)

    def test_question(self):
        dns = DNS()
        dns.add_query(DNS.Query("www.example.com", DNS.QueryType.A, DNS.QueryClass.IN))
        dns.add_query(DNS.Query("www.example2.com", DNS.QueryType.MX, DNS.QueryClass.IN))
        self.assertEquals(dns.questions_count(), 2)

        for q in dns.get_queries():
            self.assertTrue(q.name in ["www.example.com", "www.example2.com"])
            if q.name == "www.example.com":
                self.assertEquals(q.query_type, DNS.QueryType.A)
                self.assertEquals(q.query_class, DNS.QueryClass.IN)
            else:
                self.assertEquals(q.query_type, DNS.QueryType.MX)
                self.assertEquals(q.query_class, DNS.QueryClass.IN)

    def test_answers(self):
        dns = DNS()
        dns.add_answer(DNS.Resource("www.example.com", "127.0.0.1", DNS.QueryType.A, DNS.QueryClass.IN, 0x762))
        dns.add_answer(DNS.Resource("www.example2.com", "mail.example.com", DNS.QueryType.MX, DNS.QueryClass.IN, 0x762))
        self.assertEquals(dns.answers_count(), 2)
        for a in dns.get_answers():
            self.assertTrue(a.name in ["www.example.com", "www.example2.com"])
            if a.name == "www.example.com":
                self.assertEquals(a.query_type, DNS.QueryType.A)
                self.assertEquals(a.ttl, 0x762)
                self.assertEquals(a.data, "127.0.0.1")
                self.assertEquals(a.query_class, DNS.QueryClass.IN)
            else:
                self.assertEquals(a.query_type, DNS.QueryType.MX)
                self.assertEquals(a.ttl, 0x762)
                self.assertEquals(a.data, "mail.example.com")
                self.assertEquals(a.query_class, DNS.QueryClass.IN)

    def test_authority(self):
        dns = DNS()
        dns.add_authority(DNS.Resource("www.example.com", "carlos.example.com", DNS.QueryType.CNAME, DNS.QueryClass.IN, 0x762))
        dns.add_authority(DNS.Resource("www.example.com", "carlos.example.com", DNS.QueryType.CNAME, DNS.QueryClass.IN, 0x762))
        self.assertEquals(dns.authority_count(), 2)
        for auth in dns.get_authorities():
            self.assertEquals(auth.name, "www.example.com")
            self.assertEquals(auth.query_type, DNS.QueryType.CNAME)
            self.assertEquals(auth.ttl, 0x762)
            self.assertEquals(auth.data, "carlos.example.com")
            self.assertEquals(auth.query_class, DNS.QueryClass.IN)

    def test_additional(self):
        dns = DNS()
        dns.add_additional(DNS.Resource("www.example.com", "carlos.example.com", DNS.QueryType.CNAME, DNS.QueryClass.IN, 0x762))
        dns.add_additional(DNS.Resource("www.example.com", "carlos.example.com", DNS.QueryType.CNAME, DNS.QueryClass.IN, 0x762))
        self.assertEquals(dns.additional_count(), 2)
        for add in dns.get_additionals():
            self.assertEquals(add.name, "www.example.com")
            self.assertEquals(add.query_type, DNS.QueryType.CNAME)
            self.assertEquals(add.ttl, 0x762)
            self.assertEquals(add.data, "carlos.example.com")
            self.assertEquals(add.query_class, DNS.QueryClass.IN)

    def test_answers_with_same_name(self):
        dns = DNS()
        dns.add_answer(DNS.Resource("www.example.com", "127.0.0.1", DNS.QueryType.A, DNS.QueryClass.IN, 0x762))
        dns.add_answer(DNS.Resource("www.example.com", "127.0.0.2", DNS.QueryType.A, DNS.QueryClass.IN, 0x762))
        self.assertEquals(dns.answers_count(), 2)
        for a in dns.get_answers():
            self.assertEquals(a.name, "www.example.com")
            self.assertEquals(a.query_type, DNS.QueryType.A)
            self.assertEquals(a.ttl, 0x762)
            self.assertTrue(a.data in ["127.0.0.1", "127.0.0.2"])
            self.assertEquals(a.query_class, DNS.QueryClass.IN)

    def test_answers_v6(self):
        dns = DNS()
        dns.add_answer(DNS.Resource("www.example.com", "f9a8:239::1:1", DNS.QueryType.AAAA, DNS.QueryClass.IN, 0x762))
        dns.add_answer(DNS.Resource("www.example.com", "f9a8:239::1:1", DNS.QueryType.AAAA, DNS.QueryClass.IN, 0x762))
        self.assertEquals(dns.answers_count(), 2)
        for a in dns.get_answers():
            self.assertEquals(a.name, "www.example.com")
            self.assertEquals(a.query_type, DNS.QueryType.AAAA)
            self.assertEquals(a.ttl, 0x762)
            self.assertEquals(a.data, "f9a8:239::1:1")
            self.assertEquals(a.query_class, DNS.QueryClass.IN)

    def test_no_corrupt(self):
        dns = DNS.from_buffer(dns_response1)
        self.assertEquals(dns.questions_count(), 1)
        self.assertEquals(dns.answers_count(), 5)
        domain = "carlos.example.com"
        dns.add_additional(DNS.Resource("www.example.com", domain, DNS.QueryType.CNAME, DNS.QueryClass.IN, 0x762))
        dns.add_authority(DNS.Resource("www.example.com", domain, DNS.QueryType.CNAME, DNS.QueryClass.IN, 0x762))
        dns.add_query(DNS.Query("google.com", DNS.QueryType.A, DNS.QueryClass.IN))
        for q in dns.get_queries():
            self.assertEquals(q.name, "google.com")
            self.assertTrue(q.query_type in [DNS.QueryType.MX, DNS.QueryType.A])
            self.assertEquals(q.query_class, DNS.QueryClass.IN)
        for a in dns.get_answers():
            self.assertEquals(a.name, "google.com")
            self.assertEquals(a.query_type, DNS.QueryType.MX)
            self.assertEquals(a.query_class, DNS.QueryClass.IN)
            self.assertTrue(a.data in [
                "alt1.aspmx.l.google.com",
                "alt2.aspmx.l.google.com",
                "alt3.aspmx.l.google.com",
                "alt4.aspmx.l.google.com",
                "alt5.aspmx.l.google.com",
                "aspmx.l.google.com"
            ])
        for auth in dns.get_authorities():
            self.assertEquals(auth.name, "www.example.com")
            self.assertEquals(auth.query_type, DNS.QueryType.CNAME)
            self.assertEquals(auth.ttl, 0x762)
            self.assertEquals(auth.data, domain)
            self.assertEquals(auth.query_class, DNS.QueryClass.IN)
        for add in dns.get_additionals():
            self.assertEquals(add.name, "www.example.com")
            self.assertEquals(add.query_type, DNS.QueryType.CNAME)
            self.assertEquals(add.ttl, 0x762)
            self.assertEquals(add.data, domain)
            self.assertEquals(add.query_class, DNS.QueryClass.IN)
