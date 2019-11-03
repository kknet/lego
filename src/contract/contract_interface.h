#pragma once

#include <map>

#include "contract/contract_utils.h"

namespace lego {

namespace contract {

class ContractInterface {
public:
    // attr map can change, and save to block chain
    virtual int Execute(std::map<std::string, std::string>& attr_map) = 0;

protected:
    ContractInterface() {}
    virtual ~ContractInterface() {}

protected:
    DISALLOW_COPY_AND_ASSIGN(ContractInterface);

};

}  // namespace contract

}  // namespace lego
