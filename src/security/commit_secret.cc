#include "stdafx.h"
#include "security/commit_secret.h"

#include <cassert>

#include "security/crypto_utils.h"
#include "security/curve.h"
#include "security/schnorr.h"
#include "security/security_string_trans.h"

namespace lego {

namespace security {

CommitSecret::CommitSecret() : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    bool err = false;
    do {
        const Curve& curve = Schnorr::Instance()->curve();
        err = (BN_rand_range(bignum_.get(), curve.order_.get()) == 0);
        if (err) {
            CRYPTO_ERROR("Value to commit rand failed");
            break;
        }
    } while (BN_is_zero(bignum_.get()));
    inited_ = (!err);
}

CommitSecret::CommitSecret(const std::string& src) {
    try {
        bignum_ = SecurityStringTrans::Instance()->StringToBignum(src);
        if (bignum_ == nullptr) {
            CRYPTO_ERROR("Deserialization failure");
            inited_ = false;
        } else {
            inited_ = true;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with CommitSecret::Deserialize.[%s]", e.what());
        assert(false);
    }
}

CommitSecret::CommitSecret(const CommitSecret& src) : bignum_(BN_new(), BN_clear_free) {
    if (bignum_ != nullptr) {
        if (BN_copy(bignum_.get(), src.bignum_.get()) == NULL) {
            CRYPTO_ERROR("CommitSecret copy failed");
        } else {
            inited_ = true;
        }
    } else {
        CRYPTO_ERROR("Memory allocation failure");
    }
}

CommitSecret::~CommitSecret() {}

uint32_t CommitSecret::Serialize(std::string& dst) const {
    assert(inited_);
    SecurityStringTrans::Instance()->BignumToString(bignum_, dst);
    return kCommitSecretSize;
}

int CommitSecret::Deserialize(const std::string& src) {
    try {
        bignum_ = SecurityStringTrans::Instance()->StringToBignum(src);
        if (bignum_ == nullptr) {
            CRYPTO_ERROR("Deserialization failure");
            inited_ = false;
        } else {
            inited_ = true;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with CommitSecret::Deserialize.[%s]", e.what());
        return -1;
    }
    return 0;
}

CommitSecret& CommitSecret::operator=(const CommitSecret& src) {
    inited_ = (BN_copy(bignum_.get(), src.bignum_.get()) == bignum_.get());
    return *this;
}

bool CommitSecret::operator==(const CommitSecret& r) const {
    return (inited_ && r.inited_ && (BN_cmp(bignum_.get(), r.bignum_.get()) == 0));
}

}  // namespace security

}  // namespace lego
