#pragma once

#include "common/utils.h"
#include "common/log.h"

#define CONTRACT_DEBUG(fmt, ...) DEBUG("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_INFO(fmt, ...) INFO("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_WARN(fmt, ...) WARN("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_ERROR(fmt, ...) ERROR("[CONRTACT]" fmt, ## __VA_ARGS__)

namespace lego {

namespace contract {

enum ContractErrorCode {
    kContractSuccess = 0,
    kContractError = 1,
};

static const std::string kContractVpnBandwidthProveAddr = "contract_vpn_bandwith_prove";
static const std::string kContractVpnPayfor = "contract_vpn_payfor";
static const std::string kToUseBandwidthOneDay = "to_use_bw_one_day";
static const std::string kVpnClientLoginManager = "kVpnClientLoginManager";

}  // namespace contact

}  // namespace lego
