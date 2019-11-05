#pragma once

#include <unordered_map>
#include <mutex>

#include "contract/contract_interface.h"
#include "contract/contract_utils.h"

namespace lego {

namespace contract {

class ContractManager {
public:
    static ContractManager* Instance();
    int Init();
    int InitWithAttr(
            const std::string& contract_addr,
            const std::string& from,
            const std::string& to,
            uint64_t amount,
            uint32_t type,
            const std::map<std::string, std::string>& attr_map);
    virtual int Execute(
            const std::string& contract_addr,
            const std::string& from,
            const std::string& to,
            uint64_t amount,
            uint32_t type,
            std::map<std::string, std::string>& attr_map);

private:
    ContractManager() {}
    ~ContractManager() {}

    std::unordered_map<std::string, ContractInterfacePtr> contract_map_;
    std::mutex contract_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ContractManager);
};

}  // namespace contract

}  // namespace lego
