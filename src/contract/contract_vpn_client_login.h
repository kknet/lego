#pragma once

#include <unordered_map>
#include <mutex>

#include "contract/contract_interface.h"

namespace lego {

namespace contract {

class VpnClientLogin : public ContractInterface {
public:
    VpnClientLogin() {}
    virtual ~VpnClientLogin() {}
    virtual int InitWithAttr(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info);
    virtual int GetAttrWithKey(const std::string& key, std::string& value);
    virtual int Execute(bft::TxItemPtr& tx_item);

private:
    std::unordered_map<std::string, std::map<uint32_t, uint32_t>> client_login_map_;
    std::mutex client_login_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(VpnClientLogin);
};

}  // namespace contract

}  // namespace lego
