#pragma once

#include <memory>

#include <openssl/bn.h>

#include "security/commit_point.h"
#include "security/public_key.h"

namespace lego {

namespace security {

class Challenge {
public:
    Challenge();
    Challenge(
            const CommitPoint& agg_commit,
            const PublicKey& agg_pubkey,
            const std::string& message);
    Challenge(const std::string& src);
    Challenge(const Challenge& src);
    ~Challenge();
    uint32_t Serialize(std::string& dst) const;
    int Deserialize(const std::string& src);
    void Set(
            const CommitPoint& agg_commit,
            const PublicKey& agg_pubkey,
            const std::string& message);
    Challenge& operator=(const Challenge& src);
    bool operator==(const Challenge& r) const;

    bool inited() const {
        return inited_;
    }

    const std::shared_ptr<BIGNUM>& bignum() const {
        return bignum_;
    }

private:
    std::shared_ptr<BIGNUM> bignum_;
    bool inited_{ false };
};

}  // namespace security

}  // namespace lego
