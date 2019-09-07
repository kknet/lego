#pragma once

#include <unordered_map>
#include <mutex>

#include "common/utils.h"
#include "common/random.h"
#include "common/tick.h"
#include "security/ecdh_create_key.h"
#include "security/public_key.h"
#include "network/network_utils.h"

namespace lego {

namespace service {

static const uint32_t kPeerTimeout = 30 * 1000 * 1000;  // 30s

struct PeerInfo {
    PeerInfo(const std::string& pub) : pubkey(pub) {}
    bool init() {
        sec_num = common::Random::RandomInt32();
        account = network::GetAccountAddressByPublicKey(pubkey);
        security::PublicKey pub_key(pubkey);
        auto res = security::EcdhCreateKey::Instance()->CreateKey(pub_key, seckey);
        if (res != security::kSecuritySuccess) {
            return false;
        }
        timeout = std::chrono::steady_clock::now() + std::chrono::microseconds(kPeerTimeout);
        return true;
    }
    std::string pubkey;
    std::string seckey;
    int32_t sec_num;
    std::string account;
    std::chrono::steady_clock::time_point timeout;
};
typedef std::shared_ptr<PeerInfo> PeerInfoPtr;

class AccountWithSecret {
public:
    static AccountWithSecret* Instance();
    PeerInfoPtr NewPeer(const std::string& pubkey);

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