#pragma once

#include <map>
#include <memory>

#include "bft/basic_bft/transaction/tx_bft.h"
#include "contract/contract_utils.h"

namespace lego {

namespace contract {

class ContractInterface {
public:
    virtual int InitWithAttr(uint64_t block_height, bft::TxItemPtr& tx_item) = 0;
    virtual int GetAttrWithKey(const std::string& key, std::string& value) = 0;
    // attr map can change, and save to block chain
    virtual int Execute(bft::TxItemPtr& tx_item) = 0;

protected:
    ContractInterface() {}
    virtual ~ContractInterface() {}

protected:
    DISALLOW_COPY_AND_ASSIGN(ContractInterface);

};

typedef std::shared_ptr<ContractInterface> ContractInterfacePtr;

}  // namespace contract

}  // namespace lego
