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

enum ClientStatus {
    kValid = 0,
    kBandwidthFreeToUseExceeded = 1,
    kPayForExpired = 2,
    kServerOverLoaded = 3,
    kLoginByOtherTerminal = 4,
};


enum ClientPlatform {
    kUnknown = 0,
    kIos = 1,
    kAndroid = 2,
    kMac = 3,
    kWindows = 4,
};

enum VipLevel {
    kNotVip = 0,
    kVipLevel1 = 1,
    kVipLevel2 = 2,
    kVipLevel3 = 3,
    kVipLevel4 = 4,
    kVipLevel5 = 5,
};


static const std::string kClientFreeBandwidthOver = "bwo";
static const std::string kServerClientOverload = "sol";
static const std::string kCountryInvalid = "cni";

static const std::string kVpnLoginAttrKey = "vpn_login";
static const std::string kUserPayForVpn = "user_pay_for_vpn";
static const std::string kCheckVpnVersion = "tenon_vpn_url";
static const std::string kSetValidVpnClientAccount = "set_valid_vpn_client_account";
static const std::string kIncreaseVpnBandwidth = "kIncreaseVpnBandwidth";
static const std::string kVpnClientLoginAttr = "kVpnClientLoginAttr";
static const std::string kDefaultEnocdeMethod = "aes-128-cfb";
static const std::string kVpnAdminAccount = "e8a1ceb6b807a98a20e3aa10aa2199e47cbbed08c2540bd48aa3e1e72ba6bd99";
static const std::string kVpnLoginManageAccount = "008817d7557fc65cec2c212a6a8bde3e3b8672331c6e206a60dceb60391d71b8";

static const uint32_t kVpnVipMinPayfor = 66u;
static const uint32_t kVpnVipMaxPayfor = 2000u;
static const uint32_t kVpnShareStakingPrice = 1u;

}  // namespace  common

}  // namespace lego
