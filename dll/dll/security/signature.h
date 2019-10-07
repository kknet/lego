#pragma once

#include <memory>
#include <string>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "common/utils.h"

namespace lego {

namespace security {

class Signature {
public:
    Signature();
    explicit Signature(const std::string& challenge_src, const std::string& response_src);
    Signature(const Signature& src);
    ~Signature();
    Signature& operator=(const Signature& src);
    bool operator==(const Signature& r) const;
    uint32_t Serialize(std::string& challenge_dst, std::string& response_dst) const;
    int Deserialize(const std::string& challenge_src, const std::string& response_src);

    const std::shared_ptr<BIGNUM>& challenge() const {
        return challenge_;
    }

    const std::shared_ptr<BIGNUM>& response() const {
        return response_;
    }

private:
    std::shared_ptr<BIGNUM> challenge_;
    std::shared_ptr<BIGNUM> response_;

};

}  // namespace security

}  // namespace lego
