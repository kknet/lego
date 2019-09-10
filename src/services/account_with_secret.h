#pragma once

#include <unordered_map>
#include <mutex>

#include "services/vpn_server/server.h"

namespace lego {

namespace service {

class AccountWithSecret {
public:
    static AccountWithSecret* Instance();
    PeerInfoPtr NewPeer(const std::string& pubkey, const std::string& method);

private:
    AccountWithSecret();
    ~AccountWithSecret();
    void CheckPeerTimeout();

    static const uint32_t kCheckTimeoutPeriod = 30 * 1000 * 1000;

    std::unordered_map<std::string, PeerInfoPtr> pubkey_sec_map_;
    std::mutex pubkey_sec_map_mutex_;
    common::Tick tick_;

    DISALLOW_COPY_AND_ASSIGN(AccountWithSecret);
};

}  // namespace service

}  // namespace lego