#pragma once

#include <unordered_map>
#include <mutex>

#include "contract/contract_interface.h"

namespace lego {

namespace contract {

class VpnSvrBandwidth : public ContractInterface {
public:
    VpnSvrBandwidth() {}
    virtual ~VpnSvrBandwidth() {}
    virtual int InitWithAttr(
            const std::string& from,
            const std::string& to,
            uint64_t amount,
            uint32_t type,
            bool is_from,
            const std::map<std::string, std::string>& attr_map);

    virtual int Execute(
            const std::string& from,
            const std::string& to,
            uint64_t amount,
            uint32_t type,
            bool is_from,
            std::map<std::string, std::string>& attr_map);

private:
    std::unordered_map<std::string, uint32_t> bandwidth_map_;
    std::mutex bandwidth_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(VpnSvrBandwidth);
};

}  // namespace contract

}  // namespace lego
