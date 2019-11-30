#pragma once

#include <unordered_map>
#include <mutex>

#include "contract/contract_interface.h"

namespace lego {

namespace contract {

class PayforVpn : public ContractInterface {
public:
    PayforVpn() {}
    virtual ~PayforVpn() {}
    virtual int InitWithAttr(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info);
    virtual int GetAttrWithKey(const std::string& key, std::string& value);
    virtual int Execute(bft::TxItemPtr& tx_item);

private:
    std::unordered_map<std::string, uint32_t> bandwidth_all_map_;
    std::mutex bandwidth_all_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(PayforVpn);
};

}  // namespace contract

}  // namespace lego
