#include <string>
#include "wrap.h"
#include "tins/ip_address.h"
#include "tins/hw_address.h"

namespace Tins {

    WrappedIPv4Range& WrappedIPv4Range::operator=(const WrappedIPv4Range& r) {
        IPv4Range::operator=(r);
        return *this;
    }

    WrappedIPv4Range& WrappedIPv4Range::operator=(const IPv4Range& r) {
        IPv4Range::operator=(r);
        return *this;
    }

    WrappedIPv6Range& WrappedIPv6Range::operator=(const WrappedIPv6Range& r) {
        IPv6Range::operator=(r);
        return *this;
    }

    WrappedIPv6Range& WrappedIPv6Range::operator=(const IPv6Range& r) {
        IPv6Range::operator=(r);
        return *this;
    }

    WrappedHWRange& WrappedHWRange::operator=(const WrappedHWRange& r) {
        HWAddressRange::operator=(r);
        return *this;
    }

    WrappedHWRange& WrappedHWRange::operator=(const HWAddressRange& r) {
        HWAddressRange::operator=(r);
        return *this;
    }


}
