#include "security/response.h"

#include <cassert>

#include "security/crypto_utils.h"
#include "security/schnorr.h"
#include "security/security_string_trans.h"

namespace lego {

namespace security {

Response::Response() : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
}

Response::Response(
        const CommitSecret& secret,
        const Challenge& challenge,
        const PrivateKey& privkey) : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    Set(secret, challenge, privkey);
    assert(inited_);
}

Response::Response(const std::string& src) {
    int res = Deserialize(src);
    assert(res == 0);
}

Response::Response(const Response& src) : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    if (BN_copy(bignum_.get(), src.bignum_.get()) == NULL) {
        assert(false);
    } else {
        inited_ = true;
    }
}

Response::~Response() {}

uint32_t Response::Serialize(std::string& dst) const {
    if (inited_) {
        SecurityStringTrans::Instance()->BignumToString(bignum_, dst);
    }
    return kResponseSize;
}

int Response::Deserialize(const std::string& src) {
    try {
        bignum_ = SecurityStringTrans::Instance()->StringToBignum(src);
        if (bignum_ == nullptr) {
            CRYPTO_ERROR("Deserialization failure");
            inited_ = false;
        } else {
            inited_ = true;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with Response::Deserialize.[%s]", e.what());
        return -1;
    }
    return 0;
}

void Response::Set(
        const CommitSecret& secret,
        const Challenge& challenge,
        const PrivateKey& privkey) {
    if (inited_) {
        CRYPTO_ERROR("Response already initialized");
        return;
    }

    if (!secret.inited()) {
        CRYPTO_ERROR("Commit secret not initialized");
        return;
    }

    if (!challenge.inited()) {
        CRYPTO_ERROR("Challenge not initialized");
        return;
    }

    inited_ = false;
    std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        assert(false);
        return;
    }

    const Curve& curve = Schnorr::Instance()->curve();
    if (BN_mod_mul(
            bignum_.get(),
            challenge.bignum().get(),
            privkey.bignum().get(),
            curve.order_.get(),
            ctx.get()) == 0) {
        CRYPTO_ERROR("BIGNUM mod mul failed");
        return;
    }

    if (BN_mod_sub(
            bignum_.get(),
            secret.bignum().get(),
            bignum_.get(),
            curve.order_.get(),
            ctx.get()) == 0) {
        CRYPTO_ERROR("BIGNUM mod add failed");
        return;
    }

    inited_ = true;
}

Response& Response::operator=(const Response& src) {
    inited_ = (BN_copy(bignum_.get(), src.bignum_.get()) == bignum_.get());
    return *this;
}

bool Response::operator==(const Response& r) const {
    return (inited_ && r.inited_ && (BN_cmp(bignum_.get(), r.bignum_.get()) == 0));
}

}  // namespace security

}  // namespace lego
