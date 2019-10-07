#include "stdafx.h"
#include "security/signature.h"

#include <cassert>

#include "security/crypto_utils.h"
#include "security/security_string_trans.h"

namespace lego {

namespace security {

Signature::Signature()
        : challenge_(BN_new(), BN_clear_free),
          response_(BN_new(), BN_clear_free) {
    assert(challenge_ != nullptr);
    assert(response_ != nullptr);
}

Signature::Signature(const std::string& challenge_src, const std::string& response_src) {
    challenge_ = SecurityStringTrans::Instance()->StringToBignum(challenge_src);
    response_ = SecurityStringTrans::Instance()->StringToBignum(response_src);
    assert(challenge_ != nullptr);
    assert(response_ != nullptr);
}

Signature::Signature(const Signature& src)
        : challenge_(BN_new(), BN_clear_free),
          response_(BN_new(), BN_clear_free) {
    assert(challenge_ != nullptr);
    assert(response_ != nullptr);
    if (BN_copy(challenge_.get(), src.challenge_.get()) == NULL) {
        CRYPTO_ERROR("Signature challenge copy failed");
        assert(false);
    }

    if (BN_copy(response_.get(), src.response_.get()) == NULL) {
        CRYPTO_ERROR("Signature response copy failed");
        assert(false);
    }
}

Signature& Signature::operator=(const Signature& src) {
    if (BN_copy(challenge_.get(), src.challenge_.get()) == NULL) {
        CRYPTO_ERROR("Signature challenge copy failed");
        assert(false);
    }

    if (BN_copy(response_.get(), src.response_.get()) == NULL) {
        CRYPTO_ERROR("Signature response copy failed");
        assert(false);
    }

    return *this;
}

bool Signature::operator==(const Signature& r) const {
    return (BN_cmp(challenge_.get(), r.challenge_.get()) == 0) &&
            (BN_cmp(response_.get(), r.response_.get()) == 0);
}

Signature::~Signature() {}

uint32_t Signature::Serialize(std::string& challenge_dst, std::string& response_dst) const {
    SecurityStringTrans::Instance()->BignumToString(challenge_, challenge_dst);
    SecurityStringTrans::Instance()->BignumToString(response_, response_dst);
    return kChallengeSize + kResponseSize;
}

int Signature::Deserialize(const std::string& challenge_src, const std::string& response_src) {
    std::shared_ptr<BIGNUM> r_challenge = SecurityStringTrans::Instance()->StringToBignum(challenge_src);
    std::shared_ptr<BIGNUM> r_response = SecurityStringTrans::Instance()->StringToBignum(response_src);

    if ((r_challenge == nullptr) || (r_response == nullptr)) {
        CRYPTO_ERROR("BIGNUMSerialize::GetNumber failed");
        return -1;
    }

    if (BN_copy(challenge_.get(), r_challenge.get()) == NULL) {
        CRYPTO_ERROR("Signature challenge copy failed");
        return -1;
    }

    if (BN_copy(response_.get(), r_response.get()) == NULL) {
        CRYPTO_ERROR("Signature response copy failed");
        return -1;
    }
    return 0;
}

}  // namespace security

}  // namespace lego
