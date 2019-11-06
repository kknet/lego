#pragma once

#include "contract/contract_utils.h"
#include "contract/contract_vpn_login.h"

namespace lego {

namespace contract {

int VpnLogin::InitWithAttr(
        const std::string& from,
        const std::string& to,
        uint64_t amount,
        uint32_t type,
        bool is_from,
        const std::map<std::string, std::string>& attr_map) {
    return kContractSuccess;
}

int VpnLogin::Execute(
        const std::string& from,
        const std::string& to,
        uint64_t amount,
        uint32_t type,
        bool is_from,
        std::map<std::string, std::string>& attr_map) {
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
