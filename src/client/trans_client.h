#pragma once

#include "client/client_utils.h"

namespace lego {

namespace client {

class TransactionClient {
public:
    static TransactionClient* Instance();
    int Transaction(const std::string& to, uint64_t amount, std::string& gid);
    int VpnLogin(
            const std::string& svr_account,
            const std::vector<std::string>& route_vec,
            std::string& login_gid);
    int VpnLogout();

private:
    TransactionClient() {};
    ~TransactionClient() {}

    DISALLOW_COPY_AND_ASSIGN(TransactionClient);
};

}  // namespace client

}  // namespace lego
