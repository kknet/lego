#pragma once

#include <string>

namespace lego {

namespace  common {

enum ConsensusType {
    kConsensusTransaction = 0,
    kConsensusCreateAcount = 1,
    kConsensusMining = 2,
    kConsensusLogin = 3,
    kConsensusKeyValue = 4,
    kConsensusPayForCommonVpn = 5,
    kConsensusVpnBandwidth = 6,
};

static const std::string kVpnLoginAttrKey = "vpn_login";
static const std::string kUserPayForVpn = "user_pay_for_vpn";
static const std::string kIncreaseVpnBandwidth = "kIncreaseVpnBandwidth";
static const uint32_t kFreeToUseVpnBandwidth = 200 * 1024 * 1024;

}  // namespace  common

}  // namespace lego
