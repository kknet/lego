#pragma once

#include <map>
#include <memory>

#include "contract/contract_utils.h"

namespace lego {

namespace contract {

class ContractInterface {
public:
    virtual int InitWithAttr(
            const std::string& from,
            const std::string& to,
            uint64_t amount,
            uint32_t type,
            bool is_from,
            const std::map<std::string, std::string>& attr_map) = 0;

    // attr map can change, and save to block chain
    virtual int Execute(
            const std::string& from,
            const std::string& to,
            uint64_t amount,
            uint32_t type,
            bool is_from,
            std::map<std::string, std::string>& attr_map) = 0;

protected:
    ContractInterface() {}
    virtual ~ContractInterface() {}

protected:
    DISALLOW_COPY_AND_ASSIGN(ContractInterface);

};

typedef std::shared_ptr<ContractInterface> ContractInterfacePtr;

}  // namespace contract

}  // namespace lego
