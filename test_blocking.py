# encoding: utf-8

from cycapture.libpcap import BlockingSniffer, PacketWriter
from cycapture.libtins import EthernetII, IPReassembler, RAW, IP, DNS
import threading
from collections import deque
import signal
import time
import os
import logging


class ListenHTTP(threading.Thread):
    def __init__(self):
        super(ListenHTTP, self).__init__()
        self.assembler = IPReassembler()

    def run(self):
        print("start of listen HTTP")
        s = BlockingSniffer("en0", read_timeout=5000, snapshot_length=65000)
        s.filter = "tcp and port 3128"
        #s.sniff_and_store(queue)
        s.sniff_callback(self.callbackHTTP)

    def callbackHTTP(self, sec, usec, caplen, length, mview):
        ethernet_pdu = self.assembler.feed(EthernetII.from_buffer(mview))
        if ethernet_pdu is not None:
            ip = ethernet_pdu.rfind_pdu(IP)
            if ip is not None:
                #print(ip.src_addr, ip.dst_addr)
                raw = ip.rfind_pdu(RAW)
                if raw:
                    #print ("total", raw.size)
                    if raw.size < 10:
                        #print('payload', type(ip.ref_inner_pdu()), raw.payload)
                        pass


class ListenDNS(threading.Thread):
    def __init__(self):
        super(ListenDNS, self).__init__()

    def callbackDNS(self, sec, usec, caplen, mview):
        print('DNS caplen: %s %s' % (caplen, len(mview)))
        ethernet_pdu = EthernetII.from_buffer(mview)
        ip = ethernet_pdu.rfind_pdu(IP)
        print("IP is None?", ip is None)
        if ip is not None:
            print('IP from %s to %s' % (ip.src_addr, ip.dst_addr))
            raw = ethernet_pdu.rfind_pdu(RAW)
            if raw is not None:
                dns = raw.to(DNS)
                if dns is not None:
                    print("Queries from %s to %s, %s questions, %s answers" % (
                        str(ip.src_addr), str(ip.dst_addr), dns.queries_count(), dns.answers_count()
                    ))
                    print([(query.name, query.query_type, query.query_class) for query in dns.get_queries()])

    def run(self):

        print("start of listen DNS")
        s = BlockingSniffer("en0", read_timeout=5000)
        s.filter = "udp and port 53"
        s.sniff_callback(self.callbackDNS)
        #s.sniff_and_export("/Users/stef/pcap_export.pcap")


def handle_int(signum, frame):
    print('global handle SIGINT')
    BlockingSniffer.stop_all()

def main():
    global stopping_event
    q = deque()
    stopping_event = threading.Event()
    signal.signal(signal.SIGTERM, handle_int)
    signal.signal(signal.SIGINT, handle_int)
    listening_thread1 = ListenDNS()
    #listening_thread2 = ListenHTTP()

    listening_thread1.start()
    #listening_thread2.start()

    while listening_thread1.is_alive():
        time.sleep(1)
        print('main ok')
    print('end of main')


if __name__ == "__main__":
    logger = logging.getLogger('cycapture')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    main()
