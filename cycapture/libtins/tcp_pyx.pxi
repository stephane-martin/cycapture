# -*- coding: utf-8 -*-

"""
TCP packet python class
"""

cdef class TCP(PDU):
    """
    TCP packet

    When sending TCP PDUs, the checksum is calculated automatically every time you send the packet.

    While sniffing, the payload sent in each packet will be wrapped in a RAW PDU::

        >>> from cycapture.libtins import TCP, RAW
        >>> buf = ...
        >>> pdu = TCP.from_buffer(buf)
        >>> raw = pdu.rfind_pdu(RAW)
        >>> payload = raw.payload
    """
    pdu_flag = PDU.TCP
    pdu_type = PDU.TCP

    Flags = make_enum('TCP_Flags', 'Flags', 'Flags supported by the TCP PDU.', {
        'FIN': TCP_FIN,
        'SYN': TCP_SYN,
        'RST': TCP_RST,
        'PSH': TCP_PSH,
        'ACK': TCP_ACK,
        'URG': TCP_URG,
        'ECE': TCP_ECE,
        'CWR': TCP_CWR
    })

    OptionTypes = make_enum('TCP_OptionTypes', 'OptionTypes', 'Option types supported by TCP PDU', {
        'EOL': TCP_EOL,
        'NOP': TCP_NOP,
        'MSS': TCP_MSS,
        'WSCALE': TCP_WSCALE,
        'SACK_OK': TCP_SACK_OK,
        'SACK': TCP_SACK,
        'TSOPT': TCP_TSOPT,
        'ALTCHK': TCP_ALTCHK
    })

    AltChecksums = make_enum('TCP_AltChecksums', 'AltChecksums', 'Alternate checksum enum', {
        'CHK_TCP': TCP_CHK_TCP,
        'CHK_8FLETCHER': TCP_CHK_8FLETCHER,
        'CHK_16FLETCHER': TCP_CHK_16FLETCHER
    })

    def __cinit__(self, dest=0, src=0, _raw=False):
        if _raw:
            return

        if src is None:
            src = 0
        if dest is None:
            dest = 0
        self.ptr = new cppTCP(<uint16_t> int(dest), <uint16_t> int(src))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dest=0, src=0):
        """
        __init__(dest=0, src=0)

        Parameters
        ----------
        dest: uint16_t
            destination port
        src: uint16_t
            source port
        """
        pass

    property sport:
        """
        Source port (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.sport())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.sport(<uint16_t> int(value))

    property dport:
        """
        Destination port (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.dport())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.dport(<uint16_t> int(value))

    property seq:
        """
        Sequence number field (read-write, `uint32_t`)
        """
        def __get__(self):
            return int(self.ptr.seq())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.seq(<uint32_t> int(value))

    property ack_seq:
        """
        Acknowledge number field (read-write, `uint32_t`)
        """
        def __get__(self):
            return int(self.ptr.ack_seq())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.ack_seq(<uint32_t> int(value))

    property window:
        """
        Window size field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.window())
        def __set__(self, value):
            if value is None:
                value = 32678
            self.ptr.window(<uint16_t>int(value))

    property checksum:
        """
        The checksum field (read-only)
        """
        def __get__(self):
            return int(self.ptr.checksum())

    property urg_ptr:
        """
        Urgent pointer field (read-write, `uint16_t`)
        """
        def __get__(self):
            return int(self.ptr.urg_ptr())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.urg_ptr(<uint16_t>int(value))

    property data_offset:
        """
        Data offset field (read-write, `uint8_t`)
        """
        def __get__(self):
            cdef small_uint4 offset = self.ptr.data_offset()
            return <uint8_t> offset
        def __set__(self, value):
            cdef small_uint4 offset
            if value is None:
                pass            # ???
            offset = small_uint4(<uint8_t>int(value))
            self.ptr.data_offset(offset)

    # flags
    cpdef get_flag(self, flag):
        """
        get_flag(flag)
        Gets the value of a flag.

        Parameters
        ----------
        flag: :py:class:`~.TCP.Flags`

        Returns
        -------
        flag: bool
        """
        flag = TCP.Flags(flag)
        return bool(<uint8_t> self.ptr.get_flag(<TcpFlags> flag))

    cpdef set_flag(self, flag, value):
        """
        set_flag(flag, value)
        Sets a TCP flag value.

        Parameters
        ----------
        flag: :py:class:`~.TCP.Flags`
        value: bool
        """
        flag = TCP.Flags(flag)
        self.ptr.set_flag(<TcpFlags> flag, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property fin_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.FIN))
        def __set__(self, value):
            self.ptr.set_flag(TCP.Flags.FIN, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property syn_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.SYN))
        def __set__(self, value):
            self.ptr.set_flag(TCP.Flags.SYN, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property rst_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.RST))
        def __set__(self, value):
            self.ptr.set_flag(TCP.Flags.RST, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property psh_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.PSH))
        def __set__(self, value):
            self.ptr.set_flag(TCP.Flags.PSH, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property ack_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.ACK))
        def __set__(self, value):
            self.ptr.set_flag(TCP.Flags.ACK, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property urg_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.URG))
        def __set__(self, value):
            self.ptr.set_flag(TCP.Flags.URG, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property ece_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.ECE))
        def __set__(self, value):
            self.ptr.set_flag(TCP.Flags.ECE, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property cwr_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP.Flags.CWR))
        def __set__(self, value):
            self.ptr.set_flag(TCP.Flags.CWR, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property flags:
        def __get__(self):
            return <uint16_t> self.ptr.flags()
        def __set__(self, value):
            self.ptr.flags(small_uint12(<uint16_t>int(value)))

    # option
    property mss:
        def __get__(self):
            cdef uint16_t opt
            try:
                opt = self.ptr.mss()
            except OptionNotFound:
                return None
            return int(opt)
        def __set__(self, value):
            cdef tcp_pdu_option* mss_opt
            if value is None:       # back to default value
                value = 536
            self.ptr.mss(<uint16_t>int(value))

    # option
    property winscale:
        def __get__(self):
            cdef uint8_t opt
            try:
                opt = self.ptr.winscale()
            except OptionNotFound:
                return None
            return int(opt)

        def __set__(self, value):
            if value is None:
                pass            # ???
            self.ptr.winscale(<uint8_t>int(value))

    property altchecksum:
        def __get__(self):
            try:
                return TCP.AltChecksums(self.ptr.altchecksum())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = TCP.AltChecksums(value)
            self.ptr.altchecksum(<TcpAltChecksums> value)

    # option
    property sack_permitted:
        def __get__(self):
            return True if self.ptr.has_sack_permitted() else False

    # option
    cpdef set_sack_permitted(self):
        self.ptr.sack_permitted()

    property sack:
        def __get__(self):
            try:
                return <list> (self.ptr.sack())
            except OptionNotFound:
                return None

        def __set__(self, value):
            if not PySequence_Check(value):
                raise TypeError
            cdef vector[uint32_t] v
            for i in value:
                v.push_back(<uint32_t> int(i))
            self.ptr.sack(v)

    property timestamp:
        def __get__(self):
            cdef pair[uint32_t, uint32_t] p
            try:
                p = self.ptr.timestamp()
            except OptionNotFound:
                return None
            return int(p.first), int(p.second)

        def __set__(self, value):
            val, rep = value
            self.ptr.timestamp(<uint32_t> int(val), <uint32_t> int(rep))


    cpdef options(self):
        result = []
        cdef cpp_list[tcp_pdu_option] opts = self.ptr.options()
        cdef tcp_pdu_option opt
        for opt in opts:
            opt_length = int(opt.length_field())
            data_size = int(opt.data_size())
            data = b''
            if data_size > 0:
                data = <bytes>((<tcp_pdu_option>opt).data_ptr()[:data_size])
            result.append({
                'type': int(opt.option()),
                'length': opt_length,
                'data_size': data_size,
                'data': data
            })

        return result


    cdef cppPDU* replace_ptr_with_buf(self, uint8_t* buf, int size) except NULL:
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = new cppTCP(<uint8_t*> buf, <uint32_t> size)
        return self.ptr

    cdef replace_ptr(self, cppPDU* ptr):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = <cppTCP*> ptr
