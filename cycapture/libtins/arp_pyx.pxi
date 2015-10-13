# -*- coding: utf-8 -*-

cdef class ARP(PDU):
    """
    Ethernet packet
    """
    pdu_flag = PDU.ARP
    pdu_type = PDU.ARP

    Flags = IntEnum('Flags', {
        'REQUEST': ARP_REQUEST,
        'REPLY': ARP_REPLY,
    })

    def __cinit__(self, target_ip=IPv4Address(), sender_ip=IPv4Address(), target_hw=HWAddress(), sender_hw=HWAddress(), buf=None, _raw=False):
        if _raw:
            return

        cdef uint8_t* buf_addr
        cdef uint32_t size

        if buf is not None:
            PDU.prepare_buf_arg(buf, &buf_addr, &size)
            self.ptr = new cppARP(buf_addr, size)
        else:
            if not isinstance(target_ip, IPv4Address):
                target_ip = IPv4Address(target_ip)
            if not isinstance(sender_ip, IPv4Address):
                sender_ip = IPv4Address(sender_ip)
            if not isinstance(target_hw, HWAddress):
                target_hw = HWAddress(target_hw)
            if not isinstance(sender_hw, HWAddress):
                sender_hw = HWAddress(sender_hw)
            self.ptr = new cppARP(
                (<IPv4Address> target_ip).ptr[0],
                (<IPv4Address> sender_ip).ptr[0],
                (<HWAddress> target_hw).ptr[0],
                (<HWAddress> sender_hw).ptr[0]
            )

        self.base_ptr = <cppPDU*> self.ptr
        self.parent = None

    def __init__(self, target_ip=IPv4Address(), sender_ip=IPv4Address(), target_hw=HWAddress(), sender_hw=HWAddress(), buf=None, _raw=False):
        pass

    def __dealloc__(self):
        if self.ptr is not NULL and self.parent is None:
            del self.ptr
        self.ptr = NULL
        self.parent = None

    @staticmethod
    def make_arp_request(target, sender, hw_snd=HWAddress()):
        if not isinstance(target, IPv4Address):
            target = IPv4Address(target)
        if not isinstance(sender, IPv4Address):
            sender = IPv4Address(sender)
        if not isinstance(hw_snd, HWAddress):
            hw_snd = HWAddress(hw_snd)

        cdef cppEthernetII eth_pdu = cpp_make_arp_request(
            (<IPv4Address> target).ptr[0],
            (<IPv4Address> sender).ptr[0],
            (<HWAddress> hw_snd).ptr[0]
        )

        # eth_pdu will be garbaged collected at the end of this function, that's why we use the
        # clone method to make it "persistent"
        return EthernetII.factory(eth_pdu.clone(), NULL, 0, None)

    @staticmethod
    def make_arp_reply(target, sender, hw_tgt=HWAddress(), hw_snd=HWAddress()):
        if not isinstance(target, IPv4Address):
            target = IPv4Address(target)
        if not isinstance(sender, IPv4Address):
            sender = IPv4Address(sender)
        if not isinstance(hw_snd, HWAddress):
            hw_snd = HWAddress(hw_snd)
        if not isinstance(hw_tgt, HWAddress):
            hw_tgt = HWAddress(hw_tgt)

        cdef cppEthernetII eth_pdu = cpp_make_arp_reply(
            (<IPv4Address> target).ptr[0],
            (<IPv4Address> sender).ptr[0],
            (<HWAddress> hw_tgt).ptr[0],
            (<HWAddress> hw_snd).ptr[0]
        )

        return EthernetII.factory(eth_pdu.clone(), NULL, 0, None)

    property sender_hw_addr:
        def __get__(self):
            return HWAddress(<bytes>(self.ptr.sender_hw_addr().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            self.ptr.sender_hw_addr((<HWAddress> value).ptr[0])

    property target_hw_addr:
        def __get__(self):
            return HWAddress(<bytes>(self.ptr.target_hw_addr().to_string()))
        def __set__(self, value):
            if not isinstance(value, HWAddress):
                value = HWAddress(value)
            self.ptr.target_hw_addr((<HWAddress> value).ptr[0])

    property sender_ip_addr:
        def __get__(self):
            return IPv4Address(<bytes>(self.ptr.sender_ip_addr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.sender_ip_addr((<IPv4Address> value).ptr[0])

    property target_ip_addr:
        def __get__(self):
            return IPv4Address(<bytes>(self.ptr.target_ip_addr().to_string()))
        def __set__(self, value):
            if not isinstance(value, IPv4Address):
                value = IPv4Address(value)
            self.ptr.target_ip_addr((<IPv4Address> value).ptr[0])

    property hw_addr_format:
        def __get__(self):
            return self.ptr.hw_addr_format()
        def __set__(self, value):
            self.ptr.hw_addr_format(<uint16_t>int(value))

    property prot_addr_format:
        def __get__(self):
            return self.ptr.prot_addr_format()
        def __set__(self, value):
            self.ptr.prot_addr_format(<uint16_t>int(value))

    property hw_addr_length:
        def __get__(self):
            return self.ptr.hw_addr_length()
        def __set__(self, value):
            self.ptr.hw_addr_length(<uint8_t>int(value))

    property prot_addr_length:
        def __get__(self):
            return self.ptr.prot_addr_length()
        def __set__(self, value):
            self.ptr.prot_addr_length(<uint8_t>int(value))

    property opcode:
        def __get__(self):
            return self.ptr.opcode()
        def __set__(self, value):
            if isinstance(value, ARP.Flags):
                value = value.value
            self.ptr.opcode(<ARP_Flags> value)

