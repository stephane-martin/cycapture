#ifndef TINS_WRAPPER_CY
#define TINS_WRAPPER_CY

#include <string>
#include "tins/ip_address.h"
#include "tins/hw_address.h"
#include "tins/pdu.h"
#include "tins/small_uint.h"
#include "tins/ip.h"
#include "tins/pdu_option.h"
#include "tins/network_interface.h"
#include "tins/tcp.h"

namespace Tins {
    uint32_t convert_to_big_endian_int (IPv4Address& addr);
    bool network_interface_to_bool(const NetworkInterface& nwi);

    typedef HWAddress<6, uint8_t> cppHWAddress6;
    typedef PDUOption<IP::option_identifier, IP> ip_pdu_option;
    typedef PDUOption<uint8_t, TCP> tcp_pdu_option;

    //const HWAddress6 hw6_broadcast = HWAddress6::broadcast;

    typedef small_uint<1> small_uint1;
    typedef small_uint<4> small_uint4;
    typedef small_uint<12> small_uint12;
    typedef small_uint<24> small_uint24;


    PDU* cpp_find_pdu(const PDU* pdu, PDU::PDUType t);

}



#endif // TINS_WRAPPER_CY
