#pragma once

#include "client/client_utils.h"

namespace lego {

namespace client {

class TransactionClient {
public:
    static TransactionClient* Instance();
    int Transaction(
            const std::string& to,
            uint64_t amount,
            const std::string& contract_addr,
            const std::map<std::string, std::string>& attrs,
            uint32_t type,
            std::string& gid);

private:
    TransactionClient() {};
    ~TransactionClient() {}

    DISALLOW_COPY_AND_ASSIGN(TransactionClient);
};

}  // namespace client

}  // namespace lego
