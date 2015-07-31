#include <string>
#include "wrap.h"
#include "tins/ip_address.h"
#include "tins/hw_address.h"

namespace Tins {
    uint32_t convert_to_big_endian_int (IPv4Address& addr) {
        return (uint32_t)addr;
    }
    bool network_interface_to_bool(const NetworkInterface& nwi) {
        return bool(nwi);
    }
}
