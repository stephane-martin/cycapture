# encoding: utf-8

from cycapture.libpcap import BlockingSniffer
from cycapture.libtins import EthernetII
import threading
from collections import deque
import signal
import time
import os




def callback2(sec, usec, caplen, length, mview):
    print('HTTP caplen: %s' % caplen)

class Listen1(threading.Thread):
    def __init__(self):
        super(Listen1, self).__init__()

    def callback1(self, sec, usec, caplen, length, mview):
        print('DNS caplen: %s' % caplen)

    def run(self):
        print("start of listen DNS")
        s = BlockingSniffer("en0", read_timeout=5000)
        s.filter = "udp and dst port 53"
        s.sniff_callback(self.callback1)


def listen_with_callback2(queue):
    print("start of listen HTTP")
    s = BlockingSniffer("en0", read_timeout=5000)
    s.filter = "tcp and dst port 3128"
    s.sniff_and_store(queue)

def handle_term(signum, frame):
    print('global handle SIGTERM')
    # send a SIGINT to the listening threads
    BlockingSniffer.stop_all()

def handle_int(signum, frame):
    print('global handle SIGINT')
    os.kill(os.getpid(), signal.SIGTERM)

def main():
    global stopping_event
    q = deque()
    stopping_event = threading.Event()
    signal.signal(signal.SIGTERM, handle_term)
    signal.signal(signal.SIGINT, handle_int)
    listening_thread1 = Listen1()
    listening_thread2 = threading.Thread(target=listen_with_callback2, args=(q,))

    listening_thread1.start()
    listening_thread2.start()

    while listening_thread1.is_alive() and listening_thread2.is_alive():
        time.sleep(1)
        print(len(q))
    print('end of main')


if __name__ == "__main__":
    main()
