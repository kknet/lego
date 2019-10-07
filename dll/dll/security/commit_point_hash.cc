#include "stdafx.h"
#include "security/commit_point_hash.h"

#include <cassert>

#include "security/crypto_utils.h"
#include "security/sha256.h"
#include "security/curve.h"
#include "security/schnorr.h"
#include "security/security_string_trans.h"

namespace lego {

namespace security {

CommitPointHash::CommitPointHash() : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
}

CommitPointHash::CommitPointHash(const CommitPoint& point)
        : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    Set(point);
    assert(inited_);
}

CommitPointHash::CommitPointHash(const std::string& src) {
    int res = Deserialize(src);
    assert(res == 0);
    assert(inited_);
}

CommitPointHash::CommitPointHash(const CommitPointHash& src)
        : bignum_(BN_new(), BN_clear_free) {
    assert(bignum_ != nullptr);
    assert(src.bignum_ != nullptr);
    if (BN_copy(bignum_.get(), src.bignum_.get()) == NULL) {
        CRYPTO_ERROR("CommitPointHash copy failed");
        assert(false);
    } else {
        inited_ = true;
    }
}

CommitPointHash::~CommitPointHash() {}

void CommitPointHash::Set(const CommitPoint& point) {
    if (!point.inited()) {
        CRYPTO_ERROR("Commitment point not initialized");
        return;
    }

    inited_ = false;
    bytes buf(kPublicCompresssedSizeBytes);
    Sha256 sha2;
    std::string tmp_func_byte((char)kSecondHashFunctionByte, 1);
    sha2.Update(tmp_func_byte);
    const Curve& curve = Schnorr::Instance()->curve();
    if (EC_POINT_point2oct(
            curve.group_.get(),
            point.ec_point().get(),
            POINT_CONVERSION_COMPRESSED,
            buf.data(),
            kPublicCompresssedSizeBytes,
            NULL) != kPublicCompresssedSizeBytes) {
        CRYPTO_ERROR("Could not convert commitPoint to octets");
        return;
    }

    std::string tmp_buf((char*)buf.data(), buf.size());
    sha2.Update(tmp_buf);
    std::string digest = sha2.Finalize();
    if ((BN_bin2bn((unsigned char*)(digest.c_str()), digest.size(), bignum_.get())) == NULL) {
        CRYPTO_ERROR("Digest to scalar failed");
        return;
    }

    if (BN_nnmod(bignum_.get(), bignum_.get(), curve.order_.get(), NULL) == 0) {
        CRYPTO_ERROR("Could not reduce hashpoint value modulo group order");
        return;
    }
    inited_ = true;
}

CommitPointHash& CommitPointHash::operator=(const CommitPointHash& src) {
    inited_ = (BN_copy(bignum_.get(), src.bignum_.get()) != NULL);
    return *this;
}

bool CommitPointHash::operator==(const CommitPointHash& r) const {
    return (inited_ && r.inited_ && (BN_cmp(bignum_.get(), r.bignum_.get()) == 0));
}

int CommitPointHash::Deserialize(const std::string& src) {
    try {
        bignum_ = SecurityStringTrans::Instance()->StringToBignum(src);
        if (bignum_ == nullptr) {
            CRYPTO_ERROR("Deserialization failure");
            inited_ = false;
        } else {
            inited_ = true;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with CommitPointHash::Deserialize.[%s]", e.what());
        return -1;
    }
    return 0;
}

uint32_t CommitPointHash::Serialize(std::string& dst) const {
    if (inited_) {
        SecurityStringTrans::Instance()->BignumToString(bignum_, dst);
    }
    return kCommitPointHashSize;
}

}  // namespace security

}  // namespace lego
