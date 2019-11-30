#pragma once

#include "contract/contract_interface.h"

namespace lego {

namespace contract {

class VpnLogin : public ContractInterface {
public:
    VpnLogin() {}
    virtual ~VpnLogin() {}
    virtual int InitWithAttr(
            const bft::protobuf::Block& block_item,
            const bft::protobuf::TxInfo& tx_info);
    virtual int GetAttrWithKey(const std::string& key, std::string& value);
    virtual int Execute(bft::TxItemPtr& tx_item);

protected:
    DISALLOW_COPY_AND_ASSIGN(VpnLogin);
};

}  // namespace contract

}  // namespace lego
