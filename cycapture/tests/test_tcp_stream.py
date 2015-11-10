# encoding: utf-8

from cycapture.libpcap import BlockingSniffer
from cycapture.libtins import EthernetII, TCPStreamFollower

def data_callback(stream):
    print("data callback")
    print("")
    #print(stream.client_payload.tobytes())
    print("")
    #print(stream.server_payload.tobytes())
    print("")
    return True

def end_callback(stream):
    print("end callback")
    print("")
    print(stream.client_payload.tobytes())
    print("")
    print(stream.server_payload.tobytes())
    print("")
    return True

def main():
    follower = TCPStreamFollower(data_callback)
    s = BlockingSniffer("en0", read_timeout=5000, snapshot_length=65000)
    s.filter = "tcp and port 3128"
    with s.iterator(lambda p: EthernetII(buf=p), -1) as i:
        list_of_pdu = (pdu for _, _, _, pdu in i)
        follower.feed(list_of_pdu)

if __name__ == "__main__":
    main()
    print('the end')
