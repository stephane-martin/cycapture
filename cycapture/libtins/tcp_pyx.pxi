# -*- coding: utf-8 -*-
"""
TCP packet python class
"""

cdef class TCP(PDU):
    """
    TCP packet
    """
    pdu_flag = PDU.TCP
    pdu_type = PDU.TCP

    FIN = TCP_FIN
    SYN = TCP_SYN
    RST = TCP_RST
    PSH = TCP_PSH
    ACK = TCP_ACK
    URG = TCP_URG
    ECE = TCP_ECE
    CWR = TCP_CWR

    FLAGS = {b"FIN": TCP_FIN, b"SYN": TCP_SYN, b"RST": TCP_RST, b"PSH": TCP_PSH, b"ACK": TCP_ACK, b"URG": TCP_URG,
             b"ECE": TCP_ECE, b"CWR": TCP_CWR}

    FLAG_VALUES = FLAGS.values()

    EOL = TCP_EOL
    NOP = TCP_NOP
    MSS = TCP_MSS
    WSCALE = TCP_WSCALE
    SACK_OK = TCP_SACK_OK
    SACK = TCP_SACK
    TSOPT = TCP_TSOPT
    ALTCHK = TCP_ALTCHK

    map_num_to_option_type = {
        EOL: "EOL",
        NOP: "NOP",
        MSS: "MSS",
        WSCALE: "WSCALE",
        SACK_OK: "SACK_OK",
        SACK: "SACK",
        TSOPT: "TSOPT",
        ALTCHK: "ALTCHK"
    }

    CHK_TCP = TCP_CHK_TCP
    CHK_8FLETCHER = TCP_CHK_8FLETCHER
    CHK_16FLETCHER = TCP_CHK_16FLETCHER

    def __cinit__(self, dest_src_ports=None, buf=None, _raw=False):
        cdef uint8_t* buf_addr
        cdef uint32_t size
        if _raw:
            return
        elif buf is None and dest_src_ports is None:
            self.ptr = new cppTCP()
        elif buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            with nogil:
                self.ptr = new cppTCP(buf_addr, size)
        elif PyTuple_Check(dest_src_ports) or PyList_Check(dest_src_ports):
            dest, src = dest_src_ports
            if src is None:
                src = 0
            if dest is None:
                dest = 0
            self.ptr = new cppTCP(<uint16_t>int(dest), <uint16_t>int(src))
        else:
            self.ptr = new cppTCP(<uint16_t>int(dest_src_ports))
        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __dealloc__(self):
        if self.ptr != NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    def __init__(self, dest_src_ports=None, buf=None, _raw=False):
        pass

    property sport:
        def __get__(self):
            return int(self.ptr.sport())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.sport(<uint16_t> int(value))

    property dport:
        def __get__(self):
            return int(self.ptr.dport())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.dport(<uint16_t> int(value))

    property seq:
        def __get__(self):
            return int(self.ptr.seq())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.seq(<uint32_t> int(value))

    property ack_seq:
        def __get__(self):
            return int(self.ptr.ack_seq())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.ack_seq(<uint32_t> int(value))

    property window:
        def __get__(self):
            return int(self.ptr.window())
        def __set__(self, value):
            if value is None:
                value = 32678
            self.ptr.window(<uint16_t>int(value))

    property checksum:
        def __get__(self):
            return int(self.ptr.checksum())

    property urg_ptr:
        def __get__(self):
            return int(self.ptr.urg_ptr())
        def __set__(self, value):
            if value is None:
                value = 0
            self.ptr.urg_ptr(<uint16_t>int(value))

    property data_offset:
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
        if isinstance(flag, bytes):
            int_flag = self.FLAGS.get(flag.upper())
            if int_flag is None:
                raise ValueError(b"unknown flag: %s" % flag)
        else:
            int_flag = int(flag)
            if flag not in self.FLAG_VALUES:
                raise ValueError(b"Unknown flag: %s" % flag)
        return bool(<uint8_t> self.ptr.get_flag(<TcpFlags> int_flag))

    cpdef set_flag(self, flag, cpp_bool value):
        if isinstance(flag, bytes):
            int_flag = self.FLAGS.get(flag.upper())
            if int_flag is None:
                raise ValueError(b"unknown flag: %s" % flag)
        else:
            int_flag = int(flag)
            if flag not in self.FLAG_VALUES:
                raise ValueError(b"Unknown flag: %s" % flag)
        self.ptr.set_flag(<TcpFlags> int_flag, small_uint1(<uint8_t>1 if value else <uint8_t>0))


    property fin_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP_FIN))
        def __set__(self, value):
            self.ptr.set_flag(TCP_FIN, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property syn_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP_SYN))
        def __set__(self, value):
            self.ptr.set_flag(TCP_SYN, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property rst_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP_RST))
        def __set__(self, value):
            self.ptr.set_flag(TCP_RST, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property psh_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP_PSH))
        def __set__(self, value):
            self.ptr.set_flag(TCP_PSH, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property ack_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP_ACK))
        def __set__(self, value):
            self.ptr.set_flag(TCP_ACK, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property urg_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP_URG))
        def __set__(self, value):
            self.ptr.set_flag(TCP_URG, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property ece_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP_ECE))
        def __set__(self, value):
            self.ptr.set_flag(TCP_ECE, small_uint1(<uint8_t>1 if value else <uint8_t>0))

    property cwr_flag:
        def __get__(self):
            return bool(<uint8_t> self.ptr.get_flag(TCP_CWR))
        def __set__(self, value):
            self.ptr.set_flag(TCP_CWR, small_uint1(<uint8_t>1 if value else <uint8_t>0))

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

    # option
    property sack_permitted:
        def __get__(self):
            cdef cpp_bool b = self.ptr.has_sack_permitted()
            return True if b else False

    property altchecksum:
        def __get__(self):
            try:
                return int(self.ptr.altchecksum())
            except OptionNotFound:
                return None
        def __set__(self, value):
            value = int(value)
            if value not in (TCP_CHK_TCP, TCP_CHK_8FLETCHER, TCP_CHK_16FLETCHER):
                raise ValueError("Invalid checksum type")
            self.ptr.altchecksum(<TcpAltChecksums> value)

    # option
    cpdef set_sack_permitted(self):
        self.ptr.sack_permitted()


    cpdef options(self):
        result = []
        cdef cpp_list[tcp_pdu_option] opts = self.ptr.options()
        for opt in opts:
            opt_type = self.map_num_to_option_type.get(int((<tcp_pdu_option>opt).option()))
            opt_length = int((<tcp_pdu_option>opt).length_field())
            data_size = int((<tcp_pdu_option>opt).data_size())
            data = b''
            if data_size > 0:
                data = <bytes>((<tcp_pdu_option>opt).data_ptr()[:data_size])
            result.append({
                'type': opt_type,
                'length': opt_length,
                'data_size': data_size,
                'data': data
            })

        return result

