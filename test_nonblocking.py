# encoding: utf-8
__author__ = 'stef'

from cycapture.libtins import EthernetII
from tornado.ioloop import IOLoop
from tornado.gen import sleep, coroutine
from cycapture.libpcap import NonBlockingSniffer

def callback1(sec, usec, caplen, length, mview):
    print("caplen1", caplen)

q = []

@coroutine
def start1():
    global q
    s = NonBlockingSniffer("en0", read_timeout=2000)
    s.filter = "udp and dst port 53"
    s.set_loop(IOLoop.instance()).sniff_and_store(q, lambda buf: EthernetII(buf=buf))


@coroutine
def display():
    global q
    while True:
        print(q)
        yield sleep(1)

if __name__ == '__main__':
    IOLoop.instance().add_callback(start1)
    IOLoop.instance().add_callback(display)
    IOLoop.instance().start()

