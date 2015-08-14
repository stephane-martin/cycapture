# encoding: utf-8

"""
Small cython wrapper around libpcap
"""

from cpython cimport bool
from libc.stdlib cimport malloc, free
from libc.signal cimport signal as libc_signal
from libc.string cimport memcpy
# noinspection PyUnresolvedReferences
from ..make_mview cimport make_mview_from_const_uchar_buf

import logging
import threading
import struct

from .exceptions import PcapException, AlreadyActivated, SetTimeoutError, SetDirectionError, SetBufferSizeError
from .exceptions import SetSnapshotLengthError, SetPromiscModeError, SetMonitorModeError, SetNonblockingModeError
from .exceptions import ActivationError, NotActivatedError, SniffingError

ctypedef void (*sighandler_t)(int s) nogil

cdef void _do_python_callback(unsigned char* usr, const pcap_pkthdr_t* pkthdr, const unsigned char* pkt) with gil:
    (<object> (<void*> usr))(
        pkthdr.ts.tv_sec,
        pkthdr.ts.tv_usec,
        pkthdr.caplen,
        pkthdr.len,
        make_mview_from_const_uchar_buf(pkt, pkthdr.caplen)
    )


cdef void _do_c_callback(unsigned char* usr, const pcap_pkthdr_t* pkthdr, const unsigned char* pkt) nogil:
    cdef dispatch_user_param* s = <dispatch_user_param*> usr
    (s.fun)(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.caplen, pkthdr.len, pkt, s.param)


cdef void dummy_c(long tv_sec, int tv_usec, int caplen, int length, const unsigned char* pkt, void* p) nogil:
    printf("caplen %i length %i\n", caplen, length)

cdef void store_dummy_c(long tv_sec, int tv_usec, int caplen, int length, const unsigned char* pkt, void* p) nogil:
    cdef list_head* head_ptr = <list_head*> p
    cdef packet_node* temp = <packet_node*> malloc(sizeof(packet_node))
    temp.tv_sec = tv_sec
    temp.tv_usec = tv_usec
    temp.caplen = caplen
    temp.length = length
    temp.buf = <unsigned char*> malloc(caplen)
    memcpy(<void*> temp.buf, <void*>pkt, caplen)
    list_add_tail(&temp.link, head_ptr)

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


cdef class Sniffer(object):
    """
    Sniffer

    :param source: source interface
    :param read_timeout: reading timeout (default = 5000ms)
    :param buffer_size: buffer size (default = 0, default buffer size)
    :param snapshot_length: reading size for each packet (default: 2000 bytes)
    :param promisc_mode: if True, try to put the interface in promiscuous mode (default: False)
    :param monitor_mode: if True, try to put the interface in monitoring mode (default: False)
    """

    def __cinit__(self, source=None, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
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

    def __init__(self, source=None, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
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
                raise AlreadyActivated()
            if value < 0:
                value = 0
            cdef int res = pcap_set_timeout(self._handle, self._read_timeout)
            if res == 0:
                self._read_timeout = value
            else:
                raise SetTimeoutError('Error setting read timeout')

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
                raise SetDirectionError(bytes(pcap_geterr(self._handle)))

    property buffer_size:
        def __get__(self):
            return self._buffer_size

        def __set__(self, int value):
            if self._activated:
                raise AlreadyActivated()
            if value < 0:
                value = 0
            cdef int res = pcap_set_buffer_size(self._handle, self._buffer_size)
            if res == 0:
                self._buffer_size = value
            else:
                raise SetBufferSizeError("Error while setting buffer size")

    property timestamp_type:
        def __get__(self):
            return self._timestamp_type

    property snapshot_length:
        def __get__(self):
            return self._snapshot_length

        def __set__(self, int value):
            if self._activated:
                raise AlreadyActivated()
            if value < 0 or value > 65536:
                raise ValueError("snapshot_length must be 0 <= x <= 65536")
            cdef int res = pcap_set_snaplen(self._handle, value)
            if res == 0:
                self._snapshot_length = value
            else:
                raise SetSnapshotLengthError("Error setting snapshot length")

    property promisc_mode:
        def __get__(self):
            return self._promisc_mode

        def __set__(self, bool value):
            if self._activated:
                raise AlreadyActivated()
            cdef int v = 1 if value else 0
            cdef int res = pcap_set_promisc(self._handle, v)
            if res == 0:
                self._promisc_mode = value
            else:
                raise SetPromiscModeError("promisc mode could not be set")

    property monitor_mode:
        def __get__(self):
            return self._monitor_mode

        def __set__(self, bool value):
            if self._activated:
                raise AlreadyActivated()
            cdef int v = 1 if value else 0
            if pcap_set_rfmon(self._handle, v) == 0:
                self._monitor_mode = value
            else:
                raise SetMonitorModeError("monitor mode could not be set")

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
                raise SetNonblockingModeError(self._errbuf)
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
            raise ActivationError(bytes(res) + b' ' + <bytes> pcap_geterr(self._handle))
        if res < 0:
            raise ActivationError(bytes(res))
        if res > 0:
            logging.getLogger('cycapture').warning("Warning when the device was activated: %s", res)
        self._activated = True
        self.direction = self._direction
        if set_datalink:
            datalinks = [datalink[0] for datalink in self.list_datalinks()]
            if 1 in datalinks:
                # EN10MB
                self.set_datalink(1)
            elif 12 in datalinks:
                # RAW
                self.set_datalink(12)

    def __enter__(self):
        if not self._activated:
            self.activate()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    cpdef object get_datalink(self):
        if not self._activated:
            raise NotActivatedError('you must activate the device before calling get_datalink')
        cdef int res = pcap_datalink(self._handle)
        if res == PCAP_ERROR_NOT_ACTIVATED:
            raise NotActivatedError('you must activate the device before calling get_datalink')
        name, description = datalink_val_to_name_description(res)
        return res, name, description

    cpdef object list_datalinks(self):
        if not self._activated:
            raise NotActivatedError('you must activate the device before calling list_datalinks')
        cdef int* l
        results = []
        cdef int n = pcap_list_datalinks(self._handle, &l)

        if n == PCAP_ERROR_NOT_ACTIVATED:
            raise NotActivatedError('you must activate the device before calling list_datalinks')
        elif n == PCAP_ERROR:
            raise PcapException(<bytes> pcap_geterr(self._handle))
        else:
            for counter in range(n):
                name, description = datalink_val_to_name_description(l[counter])
                results.append((l[counter], name, description))
            return results

    cpdef object set_datalink(self, int dlt):
        # todo: refactor so that it can be called before activation
        if not self._activated:
            raise PcapException('you must activate the device before calling set_datalink')
        cdef int res = pcap_set_datalink(self._handle, dlt)
        if res == -1:
            raise PcapException(bytes(pcap_geterr(self._handle)))

    cpdef object set_filter(self, object filter_string, bool optimize=True, object netmask=None):
        # todo: refactor so that it can be called before activation
        if not self._activated:
            raise PcapException("you must activate the device before calling set_filter")
        if filter_string is None:
            raise ValueError("Provide a non-empty filter-string")
        filter_string = bytes(filter_string)
        if len(filter_string) == 0:
            raise ValueError("Provide a non-empty filter_string")
        cdef unsigned int netm
        if netmask is None:
            netm = PCAP_NETMASK_UNKNOWN if self._maskp == -1 else self._maskp
        else:
            netm = int(netmask)
        cdef bpf_program_t prog
        cdef int optim = 1 if optimize else 0
        cdef int res = pcap_compile(self._handle, &prog, <const char *> (<bytes> filter_string), optim, netm)
        if res != 0:
            raise PcapException(bytes(pcap_geterr(self._handle)))
        res = pcap_setfilter(self._handle, &prog)
        pcap_freecode(&prog)
        if res != 0:
            raise PcapException(bytes(pcap_geterr(self._handle)))

    cpdef sniff_callback(self, f, stopping_event=None):
        if get_current_pcap_handle() != NULL:
            raise RuntimeError("only one sniffing action is allowed")
        if stopping_event is None:
            stopping_event = threading.Event()

    cpdef sniff_and_store(self, container, stopping_event=None, f=None):
        if get_current_pcap_handle() != NULL:
            raise RuntimeError("only one sniffing action is allowed")
        if not self.activated:
            raise NotActivatedError('activate the pcap handle before trying to sniff')
        if stopping_event is None:
            stopping_event = threading.Event()

        global store_dummy_c, sig_handler

        cdef int counted
        cdef sighandler_t h, old_sigint
        cdef char* error_message = NULL
        cdef sigset_t s
        cdef dispatch_user_param usr
        cdef list_head head
        cdef list_head* cursor
        cdef list_head* nextnext
        cdef packet_node* node

        usr.fun = store_dummy_c

        with nogil:
            # this thread is only interested in SIGINT, ignore the other signals
            sigfillset(&s)
            pthread_sigmask(SIG_BLOCK, &s, NULL)
            sigemptyset(&s)
            sigaddset(&s, SIGINT)
            pthread_sigmask(SIG_UNBLOCK, &s, NULL)
            h = <sighandler_t> sig_handler
            set_current_pcap_handle(self._handle)

        while not stopping_event.is_set():
            with nogil:
                INIT_LIST_HEAD(&head)
                usr.param = <void*>&head
                old_sigint = libc_signal(SIGINT, h)
                counted = pcap_dispatch(self._handle, 0, _do_c_callback, <unsigned char*> &usr)
                libc_signal(SIGINT, old_sigint)
            try:
                cursor = head.next
                nextnext = cursor.next
                while cursor != &head:
                    node = <packet_node*>( <char *>cursor - <unsigned long> (&(<packet_node*>0).link) )
                    if f is not None:
                        container.append((
                            node.tv_sec,
                            node.tv_usec,
                            node.length,
                            f(make_mview_from_const_uchar_buf(node.buf, node.caplen))
                        ))
                    else:
                        container.append((
                            node.tv_sec,
                            node.tv_usec,
                            node.length,
                            <bytes>(node.buf[:node.caplen])
                        ))

                    free(node.buf)
                    list_del(&node.link)
                    free(node)
                    cursor = nextnext
                    nextnext = cursor.next

                if counted == -2:
                    # pcap_breakloop was called
                    stopping_event.set()
                elif counted == -1:
                    error_message = pcap_geterr(self._handle)
                    stopping_event.set()

            except KeyboardInterrupt:
                stopping_event.set()
                # memory leak can happen here
                # this 'except' clause should not trigger in the caller has installed a SIGINT handler

        set_current_pcap_handle(NULL)
        if error_message != NULL:
            raise SniffingError(bytes(error_message))


cdef void sig_handler(int signum) nogil:
    cdef pcap_t* current = get_current_pcap_handle()
    if current != NULL:
        pcap_breakloop(current)

cdef void set_current_pcap_handle(pcap_t* handle) nogil:
    global current_pcap_handle
    current_pcap_handle = handle

cdef pcap_t* get_current_pcap_handle() nogil:
    global current_pcap_handle
    return current_pcap_handle

