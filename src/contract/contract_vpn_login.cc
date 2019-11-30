#include "stdafx.h"
#include "contract/contract_vpn_login.h"

#include "contract/contract_utils.h"

namespace lego {

namespace contract {

int VpnLogin::InitWithAttr(
        const bft::protobuf::Block& block_item,
        const bft::protobuf::TxInfo& tx_info) {
    return kContractSuccess;
}

int VpnLogin::GetAttrWithKey(const std::string& key, std::string& value) {
    return kContractSuccess;
}

int VpnLogin::Execute(bft::TxItemPtr& tx_item) {
    return kContractSuccess;
}

}  // namespace contract

}  // namespace lego
