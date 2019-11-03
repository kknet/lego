#pragma once

#include "contract/contract_utils.h"
#include "contract/contract_vpn_login.h"

namespace lego {

namespace contract {

int VpnLogin::Execute(std::map<std::string, std::string>& attr_map) {
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
