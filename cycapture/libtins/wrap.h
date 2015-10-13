#ifndef TINS_WRAPPER_CY
#define TINS_WRAPPER_CY

#include <string>
#include "tins/macros.h"
#include "tins/ip_address.h"
#include "tins/hw_address.h"
#include "tins/pdu.h"
#include "tins/small_uint.h"
#include "tins/ip.h"
#include "tins/pdu_option.h"
#include "tins/network_interface.h"
#include "tins/tcp.h"
#include "tins/pppoe.h"
#include "tins/address_range.h"
#include "tins/dot11/dot11_base.h"

#ifdef BSD
#define BSD_OR_ZERO BSD
#else
#define BSD_OR_ZERO 0
#endif

namespace Tins {
    uint32_t convert_to_big_endian_int (IPv4Address& addr);
    bool network_interface_to_bool(const NetworkInterface& nwi);

    typedef HWAddress<6, uint8_t> HWAddress6;

    typedef PDUOption<IP::option_identifier, IP> ip_pdu_option;
    typedef PDUOption<uint8_t, TCP> tcp_pdu_option;
    typedef PDUOption<uint8_t, Dot11> dot11_pdu_option;
    typedef PDUOption<PPPoE::TagTypes, PPPoE> pppoe_tag;

    inline PDU* cpp_find_pdu(const PDU* pdu, PDU::PDUType t) {
        PDU* current_pdu = (PDU*) pdu;
        while(current_pdu) {
            if(current_pdu->matches_flag(t))
                return current_pdu;
            current_pdu = current_pdu->inner_pdu();
        }
        return 0;
    }


    class WrappedIPv4Range : public IPv4Range {
    public:
        WrappedIPv4Range(): IPv4Range(IPv4Address(), IPv4Address(), false) {}
        WrappedIPv4Range(const IPv4Address &first, const IPv4Address &last, bool only_hosts = false):
            IPv4Range(first, last, only_hosts) {}
        WrappedIPv4Range(const WrappedIPv4Range& r): IPv4Range(r) {}
        WrappedIPv4Range& operator=(const WrappedIPv4Range& r);
        WrappedIPv4Range& operator=(const IPv4Range& r);
    };

    class WrappedIPv6Range : public IPv6Range {
    public:
        WrappedIPv6Range(): IPv6Range(IPv6Address(), IPv6Address(), false) {}
        WrappedIPv6Range(const IPv6Address &first, const IPv6Address &last, bool only_hosts = false):
            IPv6Range(first, last, only_hosts) {}
        WrappedIPv6Range(const WrappedIPv6Range& r): IPv6Range(r) {}
        WrappedIPv6Range& operator=(const WrappedIPv6Range& r);
        WrappedIPv6Range& operator=(const IPv6Range& r);
    };

    typedef AddressRange<HWAddress6> HWAddressRange;

    class WrappedHWRange : public HWAddressRange {
    public:
        WrappedHWRange(): HWAddressRange(HWAddress6(), HWAddress6(), false) {}
        WrappedHWRange(const HWAddress6 &first, const HWAddress6 &last, bool only_hosts = false):
            HWAddressRange(first, last, only_hosts) {}
        WrappedHWRange(const WrappedHWRange& r): HWAddressRange(r) {}
        WrappedHWRange& operator=(const WrappedHWRange& r);
        WrappedHWRange& operator=(const HWAddressRange& r);

    };



}



#endif // TINS_WRAPPER_CY
