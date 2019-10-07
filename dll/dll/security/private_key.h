#pragma once

#include <string>
#include <memory>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include "common/utils.h"

namespace lego {

namespace security {

class PrivateKey {
public:
    static PrivateKey GetPrivateKeyFromString(const std::string&);

    PrivateKey();
    PrivateKey(const PrivateKey& src);
    explicit PrivateKey(const std::string& src);
    const std::shared_ptr<BIGNUM>& bignum() const {
        return bignum_;
    }
    PrivateKey& operator=(const PrivateKey&);
    bool operator==(const PrivateKey& r) const;
    uint32_t Serialize(std::string& dst) const;
    int Deserialize(const std::string& src);

private:
    std::shared_ptr<BIGNUM> bignum_;
};

}  // namespace security

}  // namespace lego
