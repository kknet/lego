#include "contract/contract_manager.h"

#include "network/route.h"
#include "network/universal_manager.h"
#include "contract/contract_vpn_svr_bandwidth.h"
#include "contract/proto/contract_proto.h"

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

    if (header.type() != common::kBlockMessage) {
        return;
    }

    protobuf::ContractMessage contract_msg;
    if (!contract_msg.ParseFromString(header.data())) {
        return;
    }

    if (contract_msg.has_get_attr_req()) {
        HandleGetContractAttrRequest(header, contract_msg);
    }
}

void ContractManager::HandleGetContractAttrRequest(
        transport::protobuf::Header& header,
        protobuf::ContractMessage& contract_msg) {
    std::string attr_value;
    if (GetAttrWithKey(
            contract_msg.get_attr_req().smart_contract_addr(),
            contract_msg.get_attr_req().attr_key(),
            attr_value) != kContractSuccess) {
        return;
    }

    protobuf::ContractMessage contract_msg;
    auto attr_res = contract_msg.mutable_get_attr_res();
    attr_res->set_smart_contract_addr(contract_msg.get_attr_req().smart_contract_addr());
    attr_res->set_attr_key(contract_msg.get_attr_req().attr_key());
    attr_res->set_attr_value(attr_value);

    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    transport::protobuf::Header msg;
    contract::ContractProto::CreateGetAttrResponse(
            dht_ptr->local_node(),
            header,
            contract_msg.SerializeAsString(),
            msg);
    network::Route::Instance()->Send(msg);
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
