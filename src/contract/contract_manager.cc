#include "contract/contract_manager.h"

#include "contract/contract_vpn_svr_bandwidth.h"

namespace lego {

namespace contract {

ContractManager* ContractManager::Instance() {
    static ContractManager ins;
    return &ins;
}

int ContractManager::Init() {
    auto vpn_bandwidth_ins = std::make_shared<VpnSvrBandwidth>();
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_);
        contract_map_[kContractVpnBandwidthProveAddr] = vpn_bandwidth_ins;
    }
    return kContractSuccess;
}

int ContractManager::InitWithAttr(
        const std::string& contract_addr,
        const std::string& from,
        const std::string& to,
        uint64_t amount,
        uint32_t type,
        bool is_from,
        const std::map<std::string, std::string>& attr_map) {
    ContractInterfacePtr contract_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_);
        auto iter = contract_map_.find(contract_addr);
        if (iter != contract_map_.end()) {
            contract_ptr = iter->second;
        }
    }

    if (contract_ptr != nullptr) {
        return contract_ptr->InitWithAttr(from, to, amount, type, is_from, attr_map);
    }
    return kContractError;
}

int ContractManager::Execute(
        const std::string& contract_addr,
        const std::string& from,
        const std::string& to,
        uint64_t amount,
        uint32_t type,
        bool is_from,
        std::map<std::string, std::string>& attr_map) {
    ContractInterfacePtr contract_ptr = nullptr;
    {
        std::lock_guard<std::mutex> guard(contract_map_mutex_);
        auto iter = contract_map_.find(contract_addr);
        if (iter != contract_map_.end()) {
            contract_ptr = iter->second;
        }
    }

    if (contract_ptr != nullptr) {
        return contract_ptr->Execute(from, to, amount, type, is_from, attr_map);
    }
    return kContractError;
}

}  // namespace contract

}  // namespace lego
