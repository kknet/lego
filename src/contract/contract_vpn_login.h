#pragma once

#include "contract/contract_interface.h"

namespace lego {

namespace contract {

class VpnLogin : public ContractInterface {
public:
    VpnLogin() {}
    virtual ~VpnLogin() {}
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

protected:
    DISALLOW_COPY_AND_ASSIGN(VpnLogin);
};

}  // namespace contract

}  // namespace lego
