#include "stdafx.h"
#include "security/private_key.h"

#include <cassert>

#include "security/schnorr.h"
#include "security/crypto_utils.h"
#include "security/security_string_trans.h"

namespace lego {

namespace security {

PrivateKey::PrivateKey() : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    const Curve& curve = Schnorr::Instance()->curve();
    do {
        if (BN_rand_range(bignum_.get(), curve.order_.get()) == 0) {
            CRYPTO_ERROR("Private key generation failed");
            break;
        }
    } while (BN_is_zero(bignum_.get()));
    std::string pri_str;
    Serialize(pri_str);
}

PrivateKey::PrivateKey(const std::string& src)
        : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    bignum_ = SecurityStringTrans::Instance()->StringToBignum(src);
}

PrivateKey::PrivateKey(const PrivateKey& src) : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    if (BN_copy(bignum_.get(), src.bignum_.get()) == NULL) {
        CRYPTO_ERROR("copy big num failed!");
        assert(false);
    }
}

PrivateKey PrivateKey::GetPrivateKeyFromString(const std::string& key) {
    assert(key.size() == 64);
    return PrivateKey(key);
}

PrivateKey& PrivateKey::operator=(const PrivateKey& src) {
    if (BN_copy(bignum_.get(), src.bignum_.get()) == NULL) {
        CRYPTO_ERROR("copy big num failed!");
        assert(false);
    }
    return *this;
}

bool PrivateKey::operator==(const PrivateKey& r) const {
    return BN_cmp(bignum_.get(), r.bignum_.get()) == 0;
}

uint32_t PrivateKey::Serialize(std::string& dst) const {
    SecurityStringTrans::Instance()->BignumToString(bignum_, dst);
    return kPrivateKeySize;
}

int PrivateKey::Deserialize(const std::string& src) {
    std::shared_ptr<BIGNUM> result = SecurityStringTrans::Instance()->StringToBignum(src);
    if (result == nullptr) {
        CRYPTO_ERROR("BIGNUMSerialize::GetNumber failed");
        return -1;
    }

    if (BN_copy(bignum_.get(), result.get()) == NULL) {
        CRYPTO_ERROR("PrivKey copy failed");
        return -1;
    }
    return 0;
}

}  // namespace security

}  // namespace lego
