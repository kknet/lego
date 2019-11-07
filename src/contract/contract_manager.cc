#include "contract/contract_manager.h"

#include "network/route.h"
#include "contract/contract_vpn_svr_bandwidth.h"

namespace lego {

namespace contract {

ContractManager* ContractManager::Instance() {
    static ContractManager ins;
    return &ins;
}

ContractManager::ContractManager() {
    Init();
    network::Route::Instance()->RegisterMessage(
            common::kContractMessage,
            std::bind(&ContractManager::HandleMessage, this, std::placeholders::_1));
}

ContractManager::~ContractManager() {}

int ContractManager::Init() {
    auto vpn_bandwidth_ins = std::make_shared<VpnSvrBandwidth>();
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_);
        contract_map_[kContractVpnBandwidthProveAddr] = vpn_bandwidth_ins;
    }
    return kContractSuccess;
}

void ContractManager::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() != common::kContractMessage) {
        return;
    }
}

int ContractManager::InitWithAttr(uint64_t block_height, const bft::protobuf::TxInfo& tx_info) {
    ContractInterfacePtr contract_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_);
        auto iter = contract_map_.find(tx_info.smart_contract_addr());
        if (iter != contract_map_.end()) {
            contract_ptr = iter->second;
        }
    }

    if (contract_ptr != nullptr) {
        return contract_ptr->InitWithAttr(block_height, tx_info);
    }
    return kContractError;
}

int ContractManager::GetAttrWithKey(
        const std::string& smart_contract_addr,
        const std::string& key,
        std::string& value) {
    ContractInterfacePtr contract_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_);
        auto iter = contract_map_.find(smart_contract_addr);
        if (iter != contract_map_.end()) {
            contract_ptr = iter->second;
        }
    }

    if (contract_ptr != nullptr) {
        return contract_ptr->GetAttrWithKey(key, value);
    }
    return kContractError;
}

int ContractManager::Execute(bft::TxItemPtr& tx_item) {
    ContractInterfacePtr contract_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_);
        auto iter = contract_map_.find(tx_item->smart_contract_addr);
        if (iter != contract_map_.end()) {
            contract_ptr = iter->second;
        }
    }

    if (contract_ptr != nullptr) {
        return contract_ptr->Execute(tx_item);
    }
    return kContractError;
}

}  // namespace contract

}  // namespace lego
