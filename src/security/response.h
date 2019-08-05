#pragma once

#include <memory>

#include <openssl/bn.h>

#include "security/challenge.h"
#include "security/private_key.h"

namespace lego {

namespace security {

class Response {
public:
    Response();
    Response(
            const CommitSecret& secret,
            const Challenge& challenge,
            const PrivateKey& privkey);
    explicit Response(const std::string& src);
    Response(const Response& src);
    ~Response();
    bool inited() const {
        return inited_;
    }
    uint32_t Serialize(std::string& dst) const;
    int Deserialize(const std::string& src);
    void Set(
            const CommitSecret& secret,
            const Challenge& challenge,
            const PrivateKey& privkey);
    Response& operator=(const Response& src);
    bool operator==(const Response& r) const;
    const std::shared_ptr<BIGNUM>& bignum() const {
        return bignum_;
    }

private:
    std::shared_ptr<BIGNUM> bignum_{ nullptr };
    bool inited_{ false };
};

}  // namespace security

}  // namespace lego
