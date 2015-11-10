# encoding: utf-8
__author__ = 'stef'

from cycapture.libtins import EthernetII
from tornado.ioloop import IOLoop
from tornado.gen import sleep, coroutine
from cycapture.libpcap import NonBlockingSniffer
import signal

stopping = False

def handle_int(signum, frame):
    global stopping
    NonBlockingSniffer.stop_all()
    stopping = True
    IOLoop.instance().stop()


def callback(sec, usec, length, mview):
    print(len(mview))


@coroutine
def start():
    s = NonBlockingSniffer("en0", read_timeout=2000)
    s.filter = "udp and dst port 53"
    # s.set_loop(IOLoop.instance()).sniff_and_store(q, lambda buf: EthernetII(buf=buf))
    # s.set_loop(IOLoop.instance()).sniff_and_export('/Users/stef/baaaa2.pcap')
    s.set_loop(IOLoop.instance()).sniff_callback(callback)

@coroutine
def display():
    global stopping
    while not stopping:
        print("balbla")
        yield sleep(1)


def setup_sighandlers():

    signal.signal(signal.SIGTERM, handle_int)
    signal.signal(signal.SIGINT, handle_int)

if __name__ == '__main__':
    setup_sighandlers()

    IOLoop.instance().add_callback(start)
    IOLoop.instance().add_callback(display)
    IOLoop.instance().start()

