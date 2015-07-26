# encoding: utf-8

"""
Small cython wrapper around libpcap
"""

# noinspection PyUnresolvedReferences
from libpcap cimport pcap_pkthdr, c_callback, sockaddr, sockaddr_in, sockaddr_in6, pcap_if_t, pcap_addr_t, pcap_t
# noinspection PyUnresolvedReferences
from libpcap cimport pcap_direction_t, bpf_program
from cpython cimport bool
import logging
import struct


cdef void _do_python_callback(unsigned char* usr, const pcap_pkthdr* pkthdr, const unsigned char* pkt) with gil:
    cdef Py_buffer pybuffer
    cdef int res = PyBuffer_FillInfo(&pybuffer, NULL, <void*> pkt, pkthdr.caplen, 1, PyBUF_FULL_RO)
    mview = PyMemoryView_FromBuffer(&pybuffer)
    (<object> (<void*> usr))(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.caplen, pkthdr.len, mview)


cdef void _do_c_callback(unsigned char* usr, const pcap_pkthdr* pkthdr, const unsigned char* pkt):
    (<c_callback> (<void*> usr))(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.caplen, pkthdr.len, pkt)


cdef void dummy_c(long tv_sec, int tv_usec, int caplen, int length, const unsigned char* pkt) with gil:
    print("override me", caplen, length)


cpdef object get_pcap_version():
    return <bytes> pcap_lib_version()


cpdef object lookupdev():
    cdef char* name
    cdef char err_buf[PCAP_ERRBUF_SIZE]
    name = pcap_lookupdev(err_buf)
    if name == NULL:
        raise PcapException(<bytes> err_buf)
    return <bytes>name


cdef object sockaddress_to_bytes(const sockaddr* sa):
    if sa == NULL:
        return b'', b''
    if sa.sa_family not in (AF_INET, AF_INET6, AF_LINK):
        return b'unknown: {}'.format(sa.sa_family), b''
    cdef int res
    cdef char hbuf[NI_MAXHOST]
    cdef char hbuf4[INET_ADDRSTRLEN]
    cdef char hbuf6[INET6_ADDRSTRLEN]
    cdef sockaddr_in* concrete4
    cdef sockaddr_in6* concrete6
    if sa.sa_family == AF_INET6:
        concrete6 = <sockaddr_in6*> sa
        if getnameinfo(sa, sizeof(concrete6[0]), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0:
            return b'ipv6', <bytes> hbuf
        return b'ipv6', b''
    elif sa.sa_family == AF_INET:
        concrete4 = <sockaddr_in*> sa
        if getnameinfo(sa, sizeof(concrete4[0]), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0:
            return b'ipv4', <bytes> hbuf
        return b'ipv4', b''
    elif sa.sa_family == AF_LINK:
        # noinspection PyUnresolvedReferences
        IF UNAME_SYSNAME == "Darwin":
            if getnameinfo(sa, sa.sa_len, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0:
                return b'link', <bytes> hbuf
            return b'link', b''
        ELSE:
            return b'link', b''


cpdef object findalldevs():
    cdef pcap_if_t* all_interfaces
    cdef pcap_if_t* first_interface
    cdef pcap_addr_t* current_address

    interfaces = []
    cdef char err_buf[PCAP_ERRBUF_SIZE]
    if pcap_findalldevs(&all_interfaces, err_buf) == -1:
        raise PcapException(<bytes> err_buf)

    first_interface = all_interfaces
    while all_interfaces != NULL:
        name = <bytes> all_interfaces.name
        description = b''
        if all_interfaces.description != NULL:
            description = <bytes> all_interfaces.description
        interface = {'name': name, 'description': description, 'addresses': [], 'flags': <int> all_interfaces.flags}
        current_address = all_interfaces.addresses
        while current_address != NULL:
            interface['addresses'].append(
                {
                    'addr': sockaddress_to_bytes(current_address.addr),
                    'netmask': sockaddress_to_bytes(current_address.netmask),
                    'dstaddr': sockaddress_to_bytes(current_address.dstaddr),
                    'broadaddr': sockaddress_to_bytes(current_address.broadaddr)
                }
            )
            current_address = current_address.next
        interfaces.append(interface)
        all_interfaces = all_interfaces.next
    pcap_freealldevs(first_interface)
    return interfaces


cdef bytes int_to_address(int i):
    return b'.'.join([bytes(ord(c)) for c in struct.pack('I', i)])


cpdef object lookupnet(bytes device):
    cdef unsigned int netp
    cdef unsigned int maskp
    cdef char errbuf[PCAP_ERRBUF_SIZE]
    if pcap_lookupnet(<char*> device, &netp, &maskp, errbuf) == 0:
        return int(netp), int(maskp), int_to_address(netp), int_to_address(maskp)
    else:
        raise PcapException(<bytes> errbuf)


cpdef object datalink_val_to_name_description(int dlt):
    cdef const char* name = pcap_datalink_val_to_name(dlt)
    cdef const char* description = pcap_datalink_val_to_description(dlt)
    cdef bytes name_b = b''
    cdef bytes description_b = b''
    if name != NULL:
        name_b = bytes(name)
    if description != NULL:
        description_b = bytes(description)
    return name_b, description_b


class PcapException(Exception):
    pass


class PcapActivatedHandle(PcapException):
    pass


cdef class _Filter(object):
    cdef bpf_program fp
    cdef bool compiled
    cdef pcap_t* handle

    def __init__(self):
        self.compiled = False
        self.handle = NULL

    cdef _Filter set_handle(self, pcap_t* handle):
        if handle == NULL:
            raise ValueError("provide a non-NULL handle")
        self.handle = handle
        return self

    cdef _Filter _compile(self, object filter_string, unsigned int netmask, bool optimize=True):
        if filter_string is None:
            raise ValueError("Provide a non-empty filter-string")
        if self.handle == NULL:
            raise PcapException("call set_handle first")
        if self.compiled:
            pcap_freecode(&self.fp)
            self.compiled = False
        cdef int optim = 1 if optimize else 0
        cdef int res = pcap_compile(self.handle, &self.fp, <const char *> (<bytes> filter_string), optim, netmask)
        if res == 0:
            self.compiled = True
            return self
        elif self.handle != NULL:
            raise PcapException(bytes(pcap_geterr(self.handle)))
        else:
            raise PcapException("should not happen...")

    cdef _Filter set(self, object filter_string, unsigned int netmask, bool optimize=True):
        if filter_string is None:
            raise ValueError("Provide a non-empty filter-string")
        if self.handle == NULL:
            raise PcapException("call set_handle first")
        self._compile(filter_string, netmask, optimize)
        cdef int res = pcap_setfilter(self.handle, &self.fp)
        if res == -1:
            if self.handle == NULL:
                raise PcapException("should not happen...")
            else:
                raise PcapException(bytes(pcap_geterr(self.handle)))
        return self

    def __dealloc__(self):
        if self.compiled:
            pcap_freecode(&self.fp)
            self.compiled = False


cdef class Sniffer(object):
    """
    Sniffer

    :param source: source interface
    :param read_timeout: reading timeout (default = 0, no timeout)
    :param buffer_size: buffer size (default = 0, default buffer size)
    :param snapshot_length: reading size for each packet (default: 1500 bytes)
    :param promisc_mode: if True, try to put the interface in promiscuous mode (default: False)
    :param monitor_mode: if True, try to put the interface in monitoring mode (default: False)
    """

    def __cinit__(self, source=None, read_timeout=0, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                  monitor_mode=False, nonblocking_mode=False, direction=PCAP_D_INOUT):
        if source is None:
            self._source = None
            self._handle = NULL
            return
        source = bytes(source)
        if len(source) == 0:
            self._source = None
            self._handle = NULL
            return
        self._source = source
        self._handle = pcap_create(<char*> source, self._errbuf)

    def __init__(self, source=None, read_timeout=0, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                 monitor_mode=False, nonblocking_mode=False, direction=PCAP_D_INOUT):
        if source is None:
            raise ValueError("Please provide a source name")
        if self._handle == NULL:
            raise PcapException("Initialization failed: " + <bytes> self._errbuf)
        self._read_timeout = int(read_timeout)
        self._buffer_size = int(buffer_size)
        self._snapshot_length = int(snapshot_length)
        self._promisc_mode = bool(promisc_mode)
        self._monitor_mode = bool(monitor_mode)
        self._timestamp_type = -1
        self._timestamp_precision = PCAP_TSTAMP_PRECISION_MICRO
        self._nonblocking_mode = nonblocking_mode
        self._activated = False
        if direction not in (PCAP_D_IN, PCAP_D_OUT, PCAP_D_INOUT):
            direction = PCAP_D_INOUT
        self._direction = direction
        try:
            self._netp, self._maskp, _, _ = lookupnet(source)     # IPV6 compatible ?
        except PcapException:
            logging.getLogger('cycapture').exception("Could not retrieve netp and masp")
            self._netp = -1
            self._maskp = -1

    property activated:
        def __get__(self):
            return self._activated

    property read_timeout:
        def __get__(self):
            return self._read_timeout

        def __set__(self, int value):
            if self._activated:
                raise PcapActivatedHandle()
            if value < 0:
                raise ValueError("read_timeout must be a positive integer")
            cdef int res = pcap_set_timeout(self._handle, self._read_timeout)
            if res == 0:
                self._read_timeout = value
            else:
                raise PcapException('Error setting read timeout')

    property direction:
        def __get__(self):
            return self._direction

        def __set__(self, int value):
            if value not in (PCAP_D_IN, PCAP_D_OUT, PCAP_D_INOUT):
                value = PCAP_D_INOUT
            cdef int res = pcap_setdirection(self._handle, <pcap_direction_t> value)
            if res == 0:
                self._direction = value
            else:
                raise PcapException(bytes(pcap_geterr(self._handle)))

    property buffer_size:
        def __get__(self):
            return self._buffer_size

        def __set__(self, int value):
            if self._activated:
                raise PcapActivatedHandle()
            if value < 0:
                raise ValueError("buffer_size must be a positive integer")
            cdef int res = pcap_set_buffer_size(self._handle, self._buffer_size)
            if res == 0:
                self._buffer_size = value
            else:
                raise PcapException("Error while setting buffer size")

    property timestamp_type:
        def __get__(self):
            return self._timestamp_type

    property snapshot_length:
        def __get__(self):
            return self._snapshot_length

        def __set__(self, int value):
            if self._activated:
                raise PcapActivatedHandle()
            if value < 0 or value > 65536:
                raise ValueError("snapshot_length must be 0 <= x <= 65536")
            cdef int res = pcap_set_snaplen(self._handle, value)
            if res == 0:
                self._snapshot_length = value
            else:
                raise PcapException("Error setting snapshot length")

    property promisc_mode:
        def __get__(self):
            return self._promisc_mode

        def __set__(self, bool value):
            if self._activated:
                raise PcapActivatedHandle()
            cdef int v = 1 if value else 0
            cdef int res = pcap_set_promisc(self._handle, v)
            if res == 0:
                self._promisc_mode = value
            else:
                raise PcapException("promisc mode could not be set")

    property monitor_mode:
        def __get__(self):
            return self._monitor_mode

        def __set__(self, bool value):
            if self._activated:
                raise PcapActivatedHandle()
            cdef int v = 1 if value else 0
            if pcap_set_rfmon(self._handle, v) == 0:
                self._monitor_mode = value
            else:
                raise PcapException("monitor mode could not be set")

    property can_set_monitor_mode:
        def __get__(self):
            cdef int res = pcap_can_set_rfmon(self._handle)
            if res == 1:
                return True, u''
            elif res == 0:
                return False, u''
            elif res == PCAP_ERROR_NO_SUCH_DEVICE:
                return False, u"the capture source specified when the handle was created doesn't exist"
            elif res == PCAP_ERROR_PERM_DENIED:
                return False, u"the process doesn't have permission to check whether monitor mode could be supported"
            elif res == PCAP_ERROR_ACTIVATED:
                return False, u"already activated"
            elif res == PCAP_ERROR:
                return False, (<bytes> pcap_geterr(self._handle)).decode('utf-8')
            else:
                raise RuntimeError("unknown error in can_set_monitor_mode: %s" % res)

    property source:
        def __get__(self):
            return self._source

    property nonblocking_mode:
        def __get__(self):
            return self._nonblocking_mode
        def __set__(self, bool mode):
            cdef int v = 1 if mode else 0
            if pcap_setnonblock(self._handle, v, self._errbuf) == -1:
                raise PcapException(self._errbuf)
            else:
                self._nonblocking_mode = mode

    cpdef object close(self):
        if self._handle != NULL:
            pcap_close(self._handle)
            self._handle = NULL
            self._activated = False

    def __dealloc__(self):
        self.close()

    cpdef object list_tstamp_types(self):
        cdef int* types
        cdef int res = pcap_list_tstamp_types(self._handle, &types)
        if res == PCAP_ERROR:
            raise PcapException(<bytes> pcap_geterr(self._handle))
        elif res <= 0:
            return []
        else:
            l = []
            for i in range(res):
                l.append(types[i])
            pcap_free_tstamp_types(types)
            return l

    cpdef object activate(self, bool set_datalink=True):
        if self._activated:
            return
        if self._handle == NULL:
            self._handle = pcap_create(<char*> self._source, self._errbuf)
        self.snapshot_length = self._snapshot_length
        self.buffer_size = self._buffer_size
        if self.can_set_monitor_mode[0]:
            self.monitor_mode = self._monitor_mode
        self.promisc_mode = self._promisc_mode
        self.read_timeout = self._read_timeout
        self.nonblocking_mode = self._nonblocking_mode
        # todo: timestamp type, timestamp precision
        cdef int res = pcap_activate(self._handle)
        if res in (PCAP_ERROR, PCAP_ERROR_PERM_DENIED, PCAP_ERROR_NO_SUCH_DEVICE):
            raise PcapException(bytes(res) + b' ' + <bytes> pcap_geterr(self._handle))
        if res < 0:
            raise PcapException(bytes(res))
        if res > 0:
            logging.getLogger('cycapture').warning("Warning when the device was activated: %s", res)
        self._activated = True
        self.direction = self._direction
        if set_datalink:
            datalinks = [datalink[0] for datalink in self.list_datalinks()]
            if 1 in datalinks:
                # EN10MB
                self.set_datalink(1)
            elif 12 in  datalinks:
                # RAW
                self.set_datalink(12)

    def __enter__(self):
        if not self._activated:
            self.activate()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    cpdef object get_datalink(self):
        if not self._activated:
            raise PcapException('you must activate the device before calling get_datalink')
        cdef int res = pcap_datalink(self._handle)
        if res == PCAP_ERROR_NOT_ACTIVATED:
            raise PcapException('you must activate the device before calling get_datalink')
        name, description = datalink_val_to_name_description(res)
        return res, name, description

    cpdef object list_datalinks(self):
        if not self._activated:
            raise PcapException('you must activate the device before calling list_datalinks')
        cdef int* l
        results = []
        cdef int n = pcap_list_datalinks(self._handle, &l)

        if n == PCAP_ERROR_NOT_ACTIVATED:
            raise PcapException('you must activate the device before calling list_datalinks')
        elif n == PCAP_ERROR:
            raise PcapException(<bytes> pcap_geterr(self._handle))
        else:
            for counter in range(n):
                name, description = datalink_val_to_name_description(l[counter])
                results.append((l[counter], name, description))
            return results

    cpdef object set_datalink(self, int dlt):
        if not self._activated:
            raise PcapException('you must activate the device before calling set_datalink')
        cdef int res = pcap_set_datalink(self._handle, dlt)
        if res == -1:
            raise PcapException(bytes(pcap_geterr(self._handle)))

    cpdef object read_n_packets(self, int cnt, object callback=None, destination=None):
        if cnt < 0:
            raise ValueError("Provide a positive packets count")
        if destination is None and callback is None:
            raise ValueError("Provide a destination or a callback")
        if destination is not None and callback is not None:
            raise ValueError("Provide a destination OR a callback")
        if destination is not None:
            if hasattr(destination, 'put'):
                return self.read_n_packets_put_destination(cnt, destination)
            if hasattr(destination, 'append'):
                return self.read_n_packets_append_destination(cnt, destination)
            raise ValueError("destination must be a list-like or a queue-like object")
        if callback is not None:
            return self.read_n_packets_python_callback(cnt, callback)

    cdef object read_n_packets_put_destination(self, int n, destination):
        pass

    cdef object read_n_packets_append_destination(self, int n, destination):
        pass

    cdef object read_n_packets_python_callback(self, int cnt, object callback):
        cdef int res = pcap_dispatch(self._handle, cnt, _do_python_callback, <unsigned char*> (<void *> callback))

    cdef object read_n_packets_c_callback(self, int cnt, c_callback callback):
        cdef int res = pcap_dispatch(self._handle, cnt, _do_c_callback, <unsigned char*> (<void *> callback))

    def dummy(self):
        global dummy_c
        cdef int counted
        while True:
            counted = pcap_dispatch(self._handle, 0, _do_c_callback, <unsigned char*> (<void *> dummy_c))
            if counted == 0:
                pass
            elif counted > 0:
                #print("%s packets have been read" % counted)
                pass
            elif counted == -2:
                print("breakloop")
            elif counted == -1:
                raise PcapException(bytes(pcap_geterr(self._handle)))


    cpdef object set_filter(self, object filter_string, bool optimize=True, object netmask=None):
        if filter_string is None:
            raise ValueError("Provide a non-empty filter-string")
        if not self._activated:
            raise PcapException("you must activate the device before calling set_filter")
        filter_string = bytes(filter_string)
        if len(filter_string) == 0:
            raise ValueError("Provide a non-empty filter_string")
        if netmask is None:
            netmask = PCAP_NETMASK_UNKNOWN if self._maskp == -1 else self._maskp
        _Filter().set_handle(self._handle).set(filter_string, int(netmask), optimize)
