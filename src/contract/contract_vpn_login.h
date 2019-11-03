#pragma once

#include "contract/contract_interface.h"

namespace lego {

namespace contract {

class VpnLogin : public ContractInterface {
public:
    VpnLogin() {}
    virtual ~VpnLogin() {}
    int Execute(std::map<std::string, std::string>& attr_map);

protected:
    DISALLOW_COPY_AND_ASSIGN(VpnLogin);
};

}  // namespace contract

}  // namespace lego
