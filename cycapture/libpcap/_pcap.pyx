# encoding: utf-8

"""
Small cython wrapper around libpcap
"""

import logging
import struct as struct_module
from ..libtins import LibtinsException as TinEx

from .exceptions import PcapException, AlreadyActivated, SetTimeoutError, SetDirectionError, SetBufferSizeError
from .exceptions import SetSnapshotLengthError, SetPromiscModeError, SetMonitorModeError, SetNonblockingModeError
from .exceptions import ActivationError, NotActivatedError, SniffingError, PermissionDenied, PromiscPermissionDenied




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
    cdef int res
    cdef pcap_if_t* all_interfaces
    cdef pcap_if_t* first_interface
    cdef pcap_addr_t* current_address

    interfaces = []
    cdef char err_buf[PCAP_ERRBUF_SIZE]
    res = pcap_findalldevs(&all_interfaces, err_buf)
    if res < 0:
        raise PcapExceptionFactory(res, <bytes> err_buf)

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
    return b'.'.join([bytes(ord(c)) for c in struct_module.pack('I', i)])


cpdef object lookupnet(bytes device):
    cdef unsigned int netp
    cdef unsigned int maskp
    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef int res
    res = pcap_lookupnet(<char*> device, &netp, &maskp, errbuf)
    if res == 0:
        return int(netp), int(maskp), int_to_address(netp), int_to_address(maskp)
    else:
        raise PcapExceptionFactory(res, <bytes> errbuf)


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


cdef class ActivationHelper(object):

    def __init__(self, sniffer_obj):
        self.sniffer_obj = sniffer_obj
        self.old_status = sniffer_obj.activated

    def __enter__(self):
        if not self.old_status:
            self.sniffer_obj._activate()

    def __exit__(self, t, value, traceback):
        if not self.old_status:
            self.sniffer_obj.close()

cdef class Sniffer(object):
    """
    Sniffer

    :param source: source interface
    :param read_timeout: reading timeout (default = 5000ms)
    :param buffer_size: buffer size (default = 0, default buffer size)
    :param snapshot_length: reading size for each packet (default: 2000 bytes)
    :param promisc_mode: if True, try to put the interface in promiscuous mode (default: False)
    :param monitor_mode: if True, try to put the interface in monitoring mode (default: False)
    :param direction: PCAP_D_INOUT, PCAP_D_OUT or PCAP_D_IN
    """

    def __cinit__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                  monitor_mode=False, direction=PCAP_D_INOUT):
        if source is None:
            self.source = None
            self._handle = NULL
            return
        source = bytes(source)
        if len(source) == 0:
            self.source = None
            self._handle = NULL
            return
        self.source = source
        self._handle = pcap_create(<char*> source, self._errbuf)

    cpdef close(self):
        if self._handle != NULL:
            pcap_close(self._handle)
        self._handle = NULL
        self.activated = False

    def __dealloc__(self):
        self.close()

    def __init__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                 monitor_mode=False, direction=PCAP_D_INOUT):
        source = bytes(source)
        if self._handle == NULL:
            raise PcapException("Initialization failed: " + <bytes> self._errbuf)
        self.read_timeout = read_timeout
        self.buffer_size = buffer_size
        self.snapshot_length = snapshot_length
        self.promisc_mode = promisc_mode
        self.monitor_mode = monitor_mode
        self.activated = False
        self.direction = direction
        self.filter = b''
        self._datalink = -1
        try:
            self._netp, self._maskp, _, _ = lookupnet(source)     # IPV6 compatible ?
        except PcapException:
            logging.getLogger('cycapture').exception("Could not retrieve netp and masp")
            self._netp = -1
            self._maskp = -1


    property read_timeout:
        def __get__(self):
            return self._read_timeout

        def __set__(self, value):
            value = int(value)
            if self.activated:
                raise AlreadyActivated()
            if value < 0:
                value = 0
            self._read_timeout = value

    cdef _apply_read_timeout(self):
        cdef int res = pcap_set_timeout(self._handle, self._read_timeout)
        if res != 0:
            raise SetTimeoutError('Error setting read timeout')

    property buffer_size:
        def __get__(self):
            return self._buffer_size

        def __set__(self, value):
            value = int(value)
            if self.activated:
                raise AlreadyActivated()
            if value < 0:
                value = 0
            self._buffer_size = value

    cdef _apply_buffer_size(self):
        cdef int res = pcap_set_buffer_size(self._handle, self._buffer_size)
        if res != 0:
            raise SetBufferSizeError("Error setting buffer size")

    property snapshot_length:
        def __get__(self):
            return self._snapshot_length

        def __set__(self, value):
            if self.activated:
                raise AlreadyActivated()
            value = int(value)
            if value < 0 or value > 65536:
                raise ValueError("snapshot_length must be 0 <= x <= 65536")
            self._snapshot_length = value

    cdef _apply_snapshot_length(self):
        cdef int res = pcap_set_snaplen(self._handle, self._snapshot_length)
        if res != 0:
            raise SetSnapshotLengthError("Error setting snapshot length")

    property promisc_mode:
        def __get__(self):
            return self._promisc_mode

        def __set__(self, bool value):
            if self.activated:
                raise AlreadyActivated()
            self._promisc_mode = 1 if value else 0

    cdef _apply_promisc_mode(self):
        cdef int res = pcap_set_promisc(self._handle, self._promisc_mode)
        if res != 0:
            raise SetPromiscModeError("promisc mode could not be set")

    property monitor_mode:
        def __get__(self):
            return self._monitor_mode

        def __set__(self, bool value):
            if self.activated:
                raise AlreadyActivated()
            cdef int v = 1 if value else 0
            can_set, reason = self.can_set_monitor_mode
            if v and not can_set:
                raise SetMonitorModeError(reason)
            self._monitor_mode = v

    cdef _apply_monitor_mode(self):
        if self._monitor_mode:
            if self.can_set_monitor_mode[0]:
                if pcap_set_rfmon(self._handle, self._monitor_mode) != 0:
                    raise SetMonitorModeError("monitor mode could not be set")

    property can_set_monitor_mode:
        def __get__(self):
            cdef int res = pcap_can_set_rfmon(self._handle)
            if res == 1:
                return True, b''
            elif res == 0:
                return False, b''
            elif res == PCAP_ERROR_NO_SUCH_DEVICE:
                return False, b"the capture source specified when the handle was created doesn't exist"
            elif res == PCAP_ERROR_PERM_DENIED:
                return False, b"the process doesn't have permission to check whether monitor mode could be supported"
            elif res == PCAP_ERROR_ACTIVATED:
                return False, b"already activated"
            elif res == PCAP_ERROR:
                return False, <bytes> pcap_geterr(self._handle)
            else:
                raise PcapExceptionFactory(res, b"error in can_set_monitor_mode: %s" % res)

    property direction:
        def __get__(self):
            return self._direction

        def __set__(self, value):
            value = int(value)
            if value not in (PCAP_D_IN, PCAP_D_OUT, PCAP_D_INOUT):
                value = PCAP_D_INOUT
            self._direction = value

    cdef _apply_direction(self):
        cdef int res = pcap_setdirection(self._handle, <pcap_direction_t> self._direction)
        if res != 0:
            raise SetDirectionError('Error setting direction')

    property filter:
        def __get__(self):
            return self._filter

        def __set__(self, value):
            value = bytes(value)
            if value:
                self._filter = value
                if self.activated:
                    self._apply_filter()

    cdef _apply_filter(self):
        cdef unsigned int netmask
        cdef bpf_program_t prog
        cdef int optim = 1
        cdef int res
        if self._filter:
            netmask = PCAP_NETMASK_UNKNOWN if self._maskp == -1 else self._maskp
            res = pcap_compile(self._handle, &prog, <const char *> (<bytes> self._filter), optim, netmask)
            if res != 0:
                raise PcapException(bytes(pcap_geterr(self._handle)))
            res = pcap_setfilter(self._handle, &prog)
            pcap_freecode(&prog)
            if res != 0:
                raise PcapException(bytes(pcap_geterr(self._handle)))


    property datalink:
        def __get__(self):
            cdef int res
            with self._activate_if_needed():
                res = pcap_datalink(self._handle)
            name, description = datalink_val_to_name_description(res)
            return res, name, description

        def __set__(self, value):
            cdef int res
            self._datalink = int(value)
            if self.activated:
                self._apply_datalink()


    cdef _apply_datalink(self):
        cdef int res
        if self._datalink == -1:
            datalinks = [datalink[0] for datalink in self.list_datalinks()]
            if 1 in datalinks:              # Ethernet
                pcap_set_datalink(self._handle, 1)
            elif 12 in datalinks:           # RAW IP
                pcap_set_datalink(self._handle, 12)
        else:
            res = pcap_set_datalink(self._handle, self._datalink)
            if res == -1:
                raise PcapException(bytes(pcap_geterr(self._handle)))

    cpdef list_datalinks(self):
        cdef int* l
        results = []
        cdef int n
        with self._activate_if_needed():
            n = pcap_list_datalinks(self._handle, &l)

            if n == PCAP_ERROR_NOT_ACTIVATED:
                raise NotActivatedError('you must activate the device before calling list_datalinks')
            elif n == PCAP_ERROR:
                raise PcapException(<bytes> pcap_geterr(self._handle))
            else:
                for counter in range(n):
                    name, description = datalink_val_to_name_description(l[counter])
                    results.append((l[counter], name, description))
                return results

    cdef _activate_if_needed(self):
        return ActivationHelper(self)

    cdef _pre_activate(self):
        if self.activated:
            return
        if self._handle == NULL:
            self._handle = pcap_create(<char*> self.source, self._errbuf)
        self._apply_read_timeout()
        self._apply_buffer_size()
        self._apply_snapshot_length()
        self._apply_monitor_mode()
        self._apply_promisc_mode()

    cdef _post_activate(self):
        if not self.activated:
            return
        self._apply_direction()
        self._apply_datalink()
        self._apply_filter()

    cdef _activate(self):
        if self.activated:
            return

        self._pre_activate()

        cdef int res = pcap_activate(self._handle)
        if res in (PCAP_ERROR, PCAP_ERROR_PERM_DENIED, PCAP_ERROR_NO_SUCH_DEVICE):
            raise PcapExceptionFactory(res, <bytes> pcap_geterr(self._handle), default=ActivationError)
        elif res < 0:
            raise PcapExceptionFactory(res, default=ActivationError)
        elif res > 0:
            logging.getLogger('cycapture').warning("Warning when the device was activated: %s", res)

        self.activated = True

        self._post_activate()


# noinspection PyAttributeOutsideInit,PyGlobalUndefined
cdef class BlockingSniffer(Sniffer):
    active_sniffers = {}

    def __cinit__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                  monitor_mode=False, direction=PCAP_D_INOUT):
        if source is None:
            self.source = None
            self._handle = NULL
            return
        source = bytes(source)
        if len(source) == 0:
            self.source = None
            self._handle = NULL
            return
        self.source = source
        self._handle = pcap_create(<char*> source, self._errbuf)
        self.parent_thread = NULL

    def __init__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                  monitor_mode=False, direction=PCAP_D_INOUT):
        Sniffer.__init__(self,source, read_timeout, buffer_size, snapshot_length, promisc_mode, monitor_mode, direction)

    def __dealloc__(self):
        self.close()

    @classmethod
    def stop_all(cls):
        # puts('stop_all method')
        for s in cls.active_sniffers.values():
            s.ask_stop()

    cpdef ask_stop(self):
        # puts('ask_stop method')
        if self.parent_thread != NULL:
            # puts('sending SIGINT to appropriate thread')
            if pthread_kill(self.parent_thread[0], SIGINT) != 0:
                raise RuntimeError("BlockingSniffer.stop (sending SIGINT) failed")

    cdef void set_signal_mask(self) nogil:
        cdef sigset_t s
        sigfillset(&s)
        pthread_sigmask(SIG_BLOCK, &s, NULL)
        sigemptyset(&s)
        sigaddset(&s, SIGINT)
        pthread_sigmask(SIG_UNBLOCK, &s, NULL)

    cdef thread_pcap_node* register(self) except NULL:
        if self in self.active_sniffers.values():
            raise RuntimeError("This BlockingSniffer is already actively listening")
        if thread_has_pcap(pthread_self()) == 1:
            raise RuntimeError("only one sniffing action per thread is allowed")
        cdef thread_pcap_node* n = register_pcap_for_thread(self._handle)
        if n == NULL:
            raise RuntimeError('register_pcap_for_thread failed')
        self.parent_thread = copy_pthread_self()
        self.active_sniffers[pthread_self_as_bytes()] = self
        cdef sighandler_t h = <sighandler_t> sig_handler
        self.old_sigint = libc_signal(SIGINT, h)
        siginterrupt(SIGINT, 1)
        return n

    cdef int unregister(self):
        libc_signal(SIGINT, self.old_sigint)
        siginterrupt(SIGINT, 1)
        cdef int res = unregister_pcap_for_thread()
        cdef bytes ident = pthread_self_as_bytes()
        if ident in self.active_sniffers:
            del self.active_sniffers[ident]
        if self.parent_thread != NULL:
            free(self.parent_thread)
            self.parent_thread = NULL
        return res



    cpdef sniff_callback(self, f, int signal_mask=1):
        global sig_handler
        cdef int counted

        cdef char* error_msg = NULL
        cdef char* error_msg_source = NULL
        cdef thread_pcap_node* node
        # keep a reference to the callback... just in case...
        self.python_callback = f
        self.python_callback_ptr = <unsigned char *> (<void*> self.python_callback)

        if signal_mask == 1:
            self.set_signal_mask()
        node = self.register()

        try:
            with self._activate_if_needed():
                # the nogil here is important: without it, the other python threads may not be able to run
                with nogil:
                    while node.asked_to_stop == 0:
                        counted = pcap_dispatch(self._handle, 0, _do_python_callback, self.python_callback_ptr)
                        if counted == -2:
                            # pcap_breakloop was called
                            node.asked_to_stop = 1
                            break
                        elif counted < 0:
                            error_msg_source = pcap_geterr(self._handle)
                            error_msg = <char *> malloc(strlen(error_msg_source) + 1)
                            if error_msg != NULL:
                                strcpy(error_msg, error_msg_source)
                            node.asked_to_stop = 1
                            break

        finally:
            self.unregister()

        if error_msg != NULL:
            msg = bytes(error_msg)
            free(error_msg)
            raise PcapExceptionFactory(counted, msg, default=SniffingError)

    cpdef sniff_and_store(self, container, f=None, int signal_mask=1):
        global store_c_callback, sig_handler
        cdef int counted
        cdef sighandler_t h = <sighandler_t> sig_handler
        cdef sighandler_t old_sigint
        cdef bytes error_message = b''
        cdef thread_pcap_node* node

        cdef dispatch_user_param usr
        cdef list_head head
        cdef list_head* cursor
        cdef list_head* nextnext
        cdef packet_node* pkt_node

        usr.fun = store_c_callback

        cdef store_fun store
        if f is None:
            store = store_packet_node_in_seq
        else:
            store = store_packet_node_in_seq_with_f


        if signal_mask == 1:
            self.set_signal_mask()
        node = self.register()


        try:
            with self._activate_if_needed():

                while node.asked_to_stop == 0:
                    with nogil:
                        INIT_LIST_HEAD(&head)
                        usr.param = <void*>&head
                        counted = pcap_dispatch(self._handle, 0, _do_c_callback, <unsigned char*> &usr)

                    cursor = head.next
                    nextnext = cursor.next
                    while cursor != &head:
                        pkt_node = <packet_node*>( <char *>cursor - <unsigned long> (&(<packet_node*>0).link) )
                        store(pkt_node, container, f)
                        free(pkt_node.buf)
                        list_del(&pkt_node.link)
                        free(pkt_node)
                        cursor = nextnext
                        nextnext = cursor.next

                    if counted == -2:
                        # pcap_breakloop was called
                        node.asked_to_stop = 1
                    elif counted < 0:
                        error_message = <bytes> (pcap_geterr(self._handle))
                        node.asked_to_stop = 1

        finally:
            self.unregister()

        if error_message:
            raise PcapExceptionFactory(counted, bytes(error_message), default=SniffingError)


# noinspection PyAttributeOutsideInit
cdef class NonBlockingSniffer(Sniffer):
    active_sniffers = {}

    def __cinit__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                  monitor_mode=False, direction=PCAP_D_INOUT):
        if source is None:
            self.source = None
            self._handle = NULL
            return
        source = bytes(source)
        if len(source) == 0:
            self.source = None
            self._handle = NULL
            return
        self.source = source
        self._handle = pcap_create(<char*> source, self._errbuf)

    def __dealloc__(self):
        self.close()

    def __init__(self, source, read_timeout=5000, buffer_size=0, snapshot_length=2000, promisc_mode=False,
                 monitor_mode=False, direction=PCAP_D_INOUT):
        Sniffer.__init__(self, source, read_timeout, buffer_size, snapshot_length, promisc_mode, monitor_mode, direction)
        self.loop = None
        self.loop_type = None
        self.descriptor = None

    cpdef set_loop(self, loop, loop_type="tornado"):
        loop_type = bytes(loop_type).lower().strip()
        self.loop = loop
        self.loop_type = loop_type
        return self

    cdef object _activate(self):
        Sniffer._activate(self)
        cdef int res
        res = pcap_setnonblock(self._handle, 1, self._errbuf)
        if res < 0:
            raise PcapExceptionFactory(res, self._errbuf, default=SetNonblockingModeError)

    def _make_tornado_handler_callback(self, callback):
        def _tornado_handler_callback(fd=None, events=None):
            cdef unsigned char* ptr = <unsigned char*> (<void*> callback)
            cdef int counted = 1
            while counted > 0:
                counted = pcap_dispatch(self._handle, 0, _do_python_callback, ptr)
        return _tornado_handler_callback

    def _make_tornado_handle_store(self, container, f):
        if f is None:
            def _cllbck(sec, usec, caplen, length, mview):
                container.append((sec, usec, length, mview.tobytes()))
        else:
            def _cllbck(sec, usec, caplen, length, mview):
                obj = f(mview)
                # if an exception happens in f, it will be caught in _do_python_callback
                if obj is not None:
                    container.append((sec, usec, length, f(mview)))

        def _tornado_handler_store(fd=None, events=None):
            cdef unsigned char* ptr = <unsigned char*> (<void*> _cllbck)
            cdef int counted = 1
            while counted > 0:
                counted = pcap_dispatch(self._handle, 0, _do_python_callback, ptr)
        return _tornado_handler_store


    cpdef sniff_callback(self, callback):
        if self in self.active_sniffers.values():
            raise RuntimeError("This NonBlockingSniffer is already actively listening")
        if self.loop is None or self.loop_type is None:
            raise RuntimeError("set loop and loop_type first")
        self.active_sniffers[id(self)] = self
        self.old_status = self.activated
        if not self.activated:
            self._activate()

        # keep a ref... so that callback can't be garbage collected
        self.python_callback = callback

        self.descriptor = pcap_get_selectable_fd(self._handle)
        if self.loop_type == "tornado":
            # "1" is for READ events
            self.loop.add_handler(self.descriptor, self._make_tornado_handler_callback(callback), 1)
        elif self.loop_type == "asyncio":
            self.loop.add_reader(self.descriptor, self._make_tornado_handler_callback(callback))
        return self.descriptor

    cpdef sniff_and_store(self, container, f=None):
        if self in self.active_sniffers.values():
            raise RuntimeError("This NonBlockingSniffer is already actively listening")
        if self.loop is None or self.loop_type is None:
            raise RuntimeError("set loop and loop_type first")
        self.active_sniffers[id(self)] = self
        self.old_status = self.activated
        self.container = container
        if not self.activated:
            self._activate()

        # keep a ref... so that callback can't be garbage collected
        self.python_callback = f

        self.descriptor = pcap_get_selectable_fd(self._handle)
        if self.loop_type == "tornado":
            # "1" is for READ events
            self.loop.add_handler(self.descriptor, self._make_tornado_handle_store(container, f), 1)
        elif self.loop_type == "asyncio":
            self.loop.add_reader(self.descriptor, self._make_tornado_handle_store(container, f))
        return self.descriptor

    cpdef stop(self):
        if self.descriptor is not None and self.loop is not None:
            if self.loop_type == "tornado":
                self.loop.remove_handler(self.descriptor)
            elif self.loop_type == "asyncio":
                self.loop.remove_reader(self.descriptor)
            self.descriptor = None
        if id(self) in self.active_sniffers:
            del self.active_sniffers[id(self)]
        if not self.old_status:
            self.close()

    @classmethod
    def stop_all(cls):
        for s in cls.active_sniffers.values():
            s.stop()

cdef void sig_handler(int signum) nogil:
    cdef thread_pcap_node* current = get_pcap_for_thread(pthread_self())
    if current != NULL:
        # puts('sig_handler: found pcap, sending breakloop')
        current.asked_to_stop = 1
        pcap_breakloop(current.handle)


cdef thread_pcap_node* get_pcap_for_thread(pthread_t thread) nogil:
    global thread_pcap_global_list
    cdef list_head* cursor = thread_pcap_global_list.next
    cdef thread_pcap_node* node
    while cursor != &thread_pcap_global_list:
        node = <thread_pcap_node*>( <char *>cursor - <unsigned long> (&(<thread_pcap_node*>0).link) )
        if pthread_equal(node.thread, thread):
            return node
        cursor = cursor.next
    return NULL

cdef thread_pcap_node* register_pcap_for_thread(pcap_t* handle) nogil:
    global lock, thread_pcap_global_list
    if pthread_mutex_lock(&lock) != 0:
        return NULL
    cdef thread_pcap_node* node
    cdef pthread_t thread = pthread_self()
    #with lock:
    if thread_has_pcap(thread) == 1:
        return NULL
    node = <thread_pcap_node*> malloc(sizeof(thread_pcap_node))
    node.thread = thread
    node.handle = handle
    node.asked_to_stop = 0
    list_add_tail(&node.link, &thread_pcap_global_list)
    pthread_mutex_unlock(&lock)
    return node

cdef int unregister_pcap_for_thread() nogil:
    global lock, thread_pcap_global_list
    if pthread_mutex_lock(&lock) != 0:
        return -1
    cdef list_head* cursor
    cdef list_head* nextnext
    cdef thread_pcap_node* node
    cdef pthread_t thread = pthread_self()
    if thread_has_pcap(thread) == 0:
        return -1
    cursor = thread_pcap_global_list.next
    nextnext = cursor.next
    while cursor != &thread_pcap_global_list:
        node = <thread_pcap_node*>( <char *>cursor - <unsigned long> (&(<thread_pcap_node*>0).link) )
        if pthread_equal(node.thread, thread):
            list_del(&node.link)
            free(node)
            break
        cursor = nextnext
        nextnext = cursor.next
    pthread_mutex_unlock(&lock)
    return 0





cpdef object PcapExceptionFactory(int return_code, bytes error_msg=b'', default=PcapException):
    # PCAP_ERROR = -1
    # PCAP_ERROR_BREAK = -2
    # PCAP_ERROR_NOT_ACTIVATED = -3
    # PCAP_ERROR_ACTIVATED = -4
    # PCAP_ERROR_NO_SUCH_DEVICE = -5
    # PCAP_ERROR_RFMON_NOTSUP = -6
    # PCAP_ERROR_NOT_RFMON = -7
    # PCAP_ERROR_PERM_DENIED = -8
    # PCAP_ERROR_IFACE_NOT_UP = -9
    # PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10
    # PCAP_ERROR_PROMISC_PERM_DENIED = -11
    # PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12

    if return_code == -3:
        return NotActivatedError(error_msg)
    elif return_code == -4:
        return AlreadyActivated(error_msg)
    elif return_code == -8:
        return PermissionDenied(error_msg)
    elif return_code == -11:
        return PromiscPermissionDenied(error_msg)
    else:
        return default(error_msg)

cdef pthread_mutex_t lock = create_error_check_lock()
INIT_LIST_HEAD(&thread_pcap_global_list)
logger = logging.getLogger('cycapture')
libpcap_version = <bytes> pcap_lib_version()
LibtinsException = TinEx



