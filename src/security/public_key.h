#pragma once

#include <memory>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include "common/utils.h"
#include "security/private_key.h"

namespace lego {

namespace security {

class PublicKey {
public:
    static PublicKey GetPubKeyFromString(const std::string&);
    PublicKey();
    explicit PublicKey(PrivateKey& privkey);
    explicit PublicKey(const std::string& src);
    PublicKey(const PublicKey&);
    ~PublicKey();
    const std::shared_ptr<EC_POINT>& ec_point() const {
        return ec_point_;
    }

    PublicKey& operator=(const PublicKey& src);
    bool operator<(const PublicKey& r) const;
    bool operator>(const PublicKey& r) const;
    bool operator==(const PublicKey& r) const;
    uint32_t Serialize(std::string& dst) const;
    int Deserialize(const std::string& src);

private:
    std::shared_ptr<EC_POINT> ec_point_;

};

}  // namespace security

}  // namespace lego
