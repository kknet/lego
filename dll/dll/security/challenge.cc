#include "stdafx.h"
#include "security/challenge.h"

#include <cassert>

#include "security/crypto_utils.h"
#include "security/sha256.h"
#include "security/schnorr.h"
#include "security/security_string_trans.h"

namespace lego {

namespace security {

Challenge::Challenge() : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
}

Challenge::Challenge(
        const CommitPoint& agg_commit,
        const PublicKey& agg_pubkey,
        const std::string& message) : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    Set(agg_commit, agg_pubkey, message);
    assert(inited_);
}

Challenge::Challenge(const std::string& src) {
    int res = Deserialize(src);
    assert(res == 0);
}

Challenge::Challenge(const Challenge& src) : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    auto res = BN_copy(bignum_.get(), src.bignum_.get());
    assert(res != nullptr);
    inited_ = true;
}

Challenge::~Challenge() {}

uint32_t Challenge::Serialize(std::string& dst) const {
    if (inited_) {
        SecurityStringTrans::Instance()->BignumToString(bignum_, dst);
    }
    return kChallengeSize;
}

int Challenge::Deserialize(const std::string& src) {
    try {
        bignum_ = SecurityStringTrans::Instance()->StringToBignum(src);
        if (bignum_ == nullptr) {
            CRYPTO_ERROR("Deserialization failure");
            inited_ = false;
        } else {
            inited_ = true;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with Challenge::Deserialize.[%s]", e.what());
        return -1;
    }
    return 0;
}

void Challenge::Set(
        const CommitPoint& agg_commit,
        const PublicKey& agg_pubkey,
        const std::string& message) {
    if (!agg_commit.inited()) {
        CRYPTO_ERROR("Aggregated commit not initialized");
        return;
    }

    if (message.size() == 0) {
        CRYPTO_ERROR("Empty message");
        return;
    }

    Sha256 sha2;
    std::string tmp_func_byte((char)kThirdHashFunctionByte, 1);
    sha2.Update(tmp_func_byte);
    inited_ = false;
    bytes buf(kPublicCompresssedSizeBytes);
    const Curve& curve = Schnorr::Instance()->curve();
    if (EC_POINT_point2oct(
            curve.group_.get(),
            agg_commit.ec_point().get(),
            POINT_CONVERSION_COMPRESSED,
            buf.data(),
            kPublicCompresssedSizeBytes,
            NULL) != kPublicCompresssedSizeBytes) {
        CRYPTO_ERROR("Could not convert commitment to octets");
        return;
    }

    std::string tmp_buf2((char*)buf.data(), buf.size());
    sha2.Update(tmp_buf2);
    fill(buf.begin(), buf.end(), 0x00);

    if (EC_POINT_point2oct(
            curve.group_.get(),
            agg_pubkey.ec_point().get(),
            POINT_CONVERSION_COMPRESSED,
            buf.data(),
            kPublicCompresssedSizeBytes,
            NULL) != kPublicCompresssedSizeBytes) {
        CRYPTO_ERROR("Could not convert public key to octets");
        return;
    }

    std::string tmp_buf((char*)buf.data(), buf.size());
    sha2.Update(tmp_buf);
    sha2.Update(message);
    std::string digest = sha2.Finalize();
    if ((BN_bin2bn((unsigned char*)digest.c_str(), digest.size(), bignum_.get())) == NULL) {
        CRYPTO_ERROR("Digest to challenge failed");
        return;
    }

    if (BN_nnmod(bignum_.get(), bignum_.get(), curve.order_.get(), NULL) == 0) {
        CRYPTO_ERROR("Could not reduce challenge modulo group order");
        return;
    }

    inited_ = true;
}

Challenge& Challenge::operator=(const Challenge& src) {
    if (this == &src) {
        return *this;
    }
    inited_ = (BN_copy(bignum_.get(), src.bignum_.get()) == bignum_.get());
    assert(inited_);
    assert(src.inited_);
    return *this;
}

bool Challenge::operator==(const Challenge& r) const {
    if (this == &r) {
        return true;
    }
    assert(inited_);
    assert(r.inited_);
    return (inited_ && r.inited_ && (BN_cmp(bignum_.get(), r.bignum_.get()) == 0));
}

}  // namespace security

}  // namespace lego
