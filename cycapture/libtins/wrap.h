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

namespace Tins {
    uint32_t convert_to_big_endian_int (IPv4Address& addr);
    bool network_interface_to_bool(const NetworkInterface& nwi);

    typedef HWAddress<6, uint8_t> cppHWAddress6;
    typedef PDUOption<IP::option_identifier, IP> ip_pdu_option;
    //const HWAddress6 hw6_broadcast = HWAddress6::broadcast;

    class small_int1 : small_uint<1> {
        public:
        uint8_t getval() const {
            return (uint8_t) *this;
        }
        small_int1(uint8_t val) : small_uint<1>(val) {};
        small_int1(small_uint<1> val) : small_uint<1>(val) {};
    };

    class small_int4 : small_uint<4> {
        public:
        uint8_t getval() const {
            return (uint8_t) *this;
        }
        small_int4(uint8_t val) : small_uint<4>(val) {};
        small_int4(small_uint<4> val) : small_uint<4>(val) {};
    };

    class small_int12 : small_uint<12> {
        public:
        uint16_t getval() const {
            return (uint16_t) *this;
        }
        small_int12(uint16_t val) : small_uint<12>(val) {};
        small_int12(small_uint<12> val) : small_uint<12>(val) {};
    };

    class small_int24 : small_uint<24> {
        public:
        uint32_t getval() const {
            return (uint32_t) *this;
        }
        small_int24(uint32_t val) : small_uint<24>(val) {};
        small_int24(small_uint<24> val) : small_uint<24>(val) {};
    };

    // workaround cython template function bug
    template<typename T>
    void slash_equals_op(T &lop, const PDU &rop) {
        PDU *last = &lop;
        while(last->inner_pdu())
            last = last->inner_pdu();
        last->inner_pdu(rop.clone());
    }

    PDU* cpp_find_pdu(const PDU* pdu, PDU::PDUType t);

}



#endif // TINS_WRAPPER_CY
