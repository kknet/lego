#pragma once

#include "common/utils.h"
#include "common/log.h"

#define CONTRACT_DEBUG(fmt, ...) DEBUG("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_INFO(fmt, ...) INFO("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_WARN(fmt, ...) WARN("[CONTRACT]" fmt, ## __VA_ARGS__)
#define CONTRACT_ERROR(fmt, ...) ERROR("[CONRTACT]" fmt, ## __VA_ARGS__)

namespace lego {

namespace contact {

enum ContractErrorCode {
    kContractSuccess = 0,
    kContractError = 1,
};

}  // namespace contact

}  // namespace lego
