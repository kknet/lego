#pragma once

#include <string>
#include <memory>

#include <openssl/bn.h>

namespace lego {

namespace security {

class CommitSecret {
public:
    CommitSecret();
    CommitSecret(const std::string& src);
    CommitSecret(const CommitSecret& src);
    ~CommitSecret();
    CommitSecret& operator=(const CommitSecret&);
    bool operator==(const CommitSecret& r) const;
    uint32_t Serialize(std::string& dst) const;
    int Deserialize(const std::string& src);

    bool inited() const {
        return inited_;
    }

    const std::shared_ptr<BIGNUM>& bignum() const {
        return bignum_;
    }

    std::shared_ptr<BIGNUM>& mutable_bignum() {
        return bignum_;
    }

private:
    std::shared_ptr<BIGNUM> bignum_;
    bool inited_{ false };
};

}  // namespace security

}  // namespace lego
