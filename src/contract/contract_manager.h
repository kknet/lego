#pragma once

#include <unordered_map>
#include <mutex>

#include "contract/contract_interface.h"
#include "contract/contract_utils.h"
#include "contract/proto/contract.pb.h"

namespace lego {

namespace contract {

class ContractManager {
public:
    static ContractManager* Instance();
    int Init();
    int InitWithAttr(uint64_t block_height, const bft::protobuf::TxInfo& tx_info);
    int GetAttrWithKey(
            const std::string& smart_contract_addr,
            const std::string& key,
            std::string& value);
    virtual int Execute(bft::TxItemPtr& tx_item);

private:
    ContractManager();
    ~ContractManager();
    void HandleMessage(transport::protobuf::Header& header);
    void HandleGetContractAttrRequest(
            transport::protobuf::Header& header,
            protobuf::ContractMessage& block_msg);

    std::unordered_map<std::string, ContractInterfacePtr> contract_map_;
    std::mutex contract_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ContractManager);
};

}  // namespace contract

}  // namespace lego
