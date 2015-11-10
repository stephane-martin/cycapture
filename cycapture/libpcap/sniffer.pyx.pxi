# -*- coding: utf-8 -*-

cdef class BaseSniffer(object):
    """
    Sniffer base class
    """

    DIRECTION = make_enum('DIRECTION', 'DIRECTION', 'Sniffing direction', {
        'PCAP_D_INOUT': PCAP_D_INOUT,
        'PCAP_D_IN': PCAP_D_IN,
        'PCAP_D_OUT': PCAP_D_OUT
    })

    DLT = make_enum('BaseSniffer_DLT', 'DLT', 'Datalink types', {
        'DLT_NULL': DLT_NULL,
        'DLT_EN10MB': DLT_EN10MB,
        'DLT_EN3MB': DLT_EN3MB,
        'DLT_AX25': DLT_AX25,
        'DLT_PRONET': DLT_PRONET,
        'DLT_CHAOS': DLT_CHAOS,
        'DLT_IEEE802': DLT_IEEE802,
        'DLT_ARCNET': DLT_ARCNET,
        'DLT_SLIP': DLT_SLIP,
        'DLT_PPP': DLT_PPP,
        'DLT_FDDI': DLT_FDDI,
        'DLT_RAW': DLT_RAW,
        'DLT_IEEE802_11': DLT_IEEE802_11,
        'DLT_LOOP': DLT_LOOP,
        'DLT_ENC': DLT_ENC,
        'DLT_PRISM_HEADER': DLT_PRISM_HEADER,
        'DLT_AIRONET_HEADER': DLT_AIRONET_HEADER,
        'DLT_IEEE802_11_RADIO': DLT_IEEE802_11_RADIO,
        'DLT_IEEE802_11_RADIO_AVS': DLT_IEEE802_11_RADIO_AVS,
        'DLT_IPV4': DLT_IPV4,
        'DLT_IPV6': DLT_IPV6
    })

    def __cinit__(self, interface=None, filename=None, int read_timeout=5000, int buffer_size=0, int snapshot_length=2000,
                  promisc_mode=False, monitor_mode=False, direction=BaseSniffer.DIRECTION.PCAP_D_INOUT):

        if interface is None and filename is None:
            raise ValueError("provide interface or filename")
        elif interface is not None and filename is not None:
            raise ValueError("provide interface OR filename")

        if interface is not None:
            self.interface = bytes(interface)       # supports NetworkInterface objects!
            if len(interface) == 0:
                raise ValueError("interface can't be empty")
            try:
                self._netp, self._maskp, _, _ = lookupnet(interface)     # IPV6 compatible ?
            except PcapException:
                logging.getLogger('cycapture').exception("Could not retrieve netp and masp")
                self._netp = -1
                self._maskp = -1

        else:
            self.filename = bytes(filename)
            if len(filename) == 0:
                raise ValueError("filename can't be empty")
            elif not exists(filename):
                raise ValueError("file '%s' does not exist" % filename)
            self._netp = -1
            self._maskp = -1

        self._set_pcap_handle()

    def __init__(self, interface=None, filename=None, int read_timeout=5000, int buffer_size=0, int snapshot_length=2000,
                  promisc_mode=False, monitor_mode=False, direction=BaseSniffer.DIRECTION.PCAP_D_INOUT):
        """
        __init__(interface=None, filename=None, int read_timeout=5000, int buffer_size=0, int snapshot_length=2000, promisc_mode=False, monitor_mode=False, direction=PCAP_D_INOUT)

        Parameters
        ----------
        interface: bytes
            which interface to sniff on
        filename: file or bytes
            which file to get the packets from
        read_timeout: int
            if read_timeout > 0, wait at most read_timeout miliseconds to (batch-) deliver the captured packets
        buffer_size: int
            platform buffer size in bytes for captured packets. 0 means 'use system default'.
        snapshot_length: int
            only the first snaplen_length bytes of each packet will be captured and provided as packet data
        promisc_mode: bool
            a mode in which all packets, even if they are not sent to an address that the adapter recognizes, are provided
        monitor_mode: bool
            in monitor mode ("Radio Frequency MONitor"), the interface will supply all frames that it receives, with
            802.11 headers.
        direction: :py:class:`~.BaseSniffer.DIRECTION`
            set direction to capture only  packets received by the machine or only packets sent by the machine
        """

        self.read_timeout = read_timeout
        self.buffer_size = buffer_size
        self.snapshot_length = snapshot_length
        self.promisc_mode = promisc_mode
        self.monitor_mode = monitor_mode
        self.activated = False
        self.direction = direction
        self.filter = b''
        self._datalink = -1

    cdef _set_pcap_handle(self):
        if self._handle != NULL:
            return
        if self.interface is not None:
            self._handle = pcap_create(<char*> self.interface, self._errbuf)
        else:
            self._handle = pcap_open_offline(<const char *> self.filename, self._errbuf)
        if self._handle == NULL:
            raise PcapException("Initialization failed: " + <bytes> self._errbuf)

    cpdef close(self):
        if self._handle != NULL:
            pcap_close(self._handle)
        self._handle = NULL
        self.activated = False

    def __dealloc__(self):
        self.close()

    property read_timeout:
        """
        PCAP read timeout in miliseconds (`int`)
        """
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
        """
        PCAP buffer size in bytes (`int`)
        """
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
        """
        PCAP snapshot length in bytes (`int`)
        """
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
        """
        PCAP promisc mode (`bool`)
        """
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
        """
        PCAP monitoring mode (`bool`)
        """
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
        """
        Whether the monitoring mode is available (read-only, `bool`)
        """
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
        """
        Capture direction (:py:class:`~.BaseSniffer.DIRECTION`)
        """
        def __get__(self):
            return self._direction

        def __set__(self, value):
            self._direction = BaseSniffer.DIRECTION(value)

    cdef _apply_direction(self):
        cdef int res = pcap_setdirection(self._handle, <pcap_direction_t> self._direction)
        if res != 0:
            raise SetDirectionError('Error setting direction')

    property filter:
        """
        PCAP filter (`bytes`)

        .. seealso:: `pcap filter syntax manual page <http://www.tcpdump.org/manpages/pcap-filter.7.html>`_
        """
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
        """
        PCAP datalink type (:py:class:`~.BaseSniffer.DLT`)
        """
        def __get__(self):
            cdef int res
            with self.activate_if_needed():
                res = pcap_datalink(self._handle)
            name, description = datalink_to_description(res)
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
        """
        list_datalinks()
        List the datalink types supported by the interface.

        Returns
        -------
        datalink types: list of (int, bytes, bytes)
        """
        cdef int* l
        results = []
        cdef int n
        with self.activate_if_needed():
            n = pcap_list_datalinks(self._handle, &l)

            if n == PCAP_ERROR_NOT_ACTIVATED:
                raise NotActivatedError('you must activate the device before calling list_datalinks')
            elif n == PCAP_ERROR:
                raise PcapException(<bytes> pcap_geterr(self._handle))
            else:
                for counter in range(n):
                    name, description = datalink_to_description(l[counter])
                    results.append((l[counter], name, description))
                return results

    cdef activate_if_needed(self):
        return ActivationHelper(self)

    cdef _pre_activate(self):
        if self.activated:
            return
        self._set_pcap_handle()
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

    cdef activate(self):
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


cdef class ActivationHelper(object):

    def __init__(self, sniffer_obj):
        self.sniffer_obj = sniffer_obj
        self.old_status = sniffer_obj.activated

    def __enter__(self):
        if not self.old_status:
            self.sniffer_obj.activate()

    def __exit__(self, t, value, traceback):
        if not self.old_status:
            self.sniffer_obj.close()

include "blocking_sniffer.pyx.pxi"
include "nonblocking_sniffer.pyx.pxi"
