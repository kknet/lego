#include "security/commit_point.h"

#include "security/schnorr.h"
#include "security/crypto_utils.h"
#include "security/security_string_trans.h"

namespace lego {

namespace security {

CommitPoint::CommitPoint()
        : ec_point_(
          EC_POINT_new(Schnorr::Instance()->curve().group_.get()),
          EC_POINT_clear_free) {
    assert(ec_point_ != nullptr);
}

CommitPoint::CommitPoint(CommitSecret& secret)
        : ec_point_(
          EC_POINT_new(Schnorr::Instance()->curve().group_.get()),
          EC_POINT_clear_free) {
    assert(ec_point_ != nullptr);
    Set(secret);
}

CommitPoint::CommitPoint(const std::string& src) {
    try {
        ec_point_ = SecurityStringTrans::Instance()->StringToEcPoint(src);
        if (ec_point_ == nullptr) {
            CRYPTO_ERROR("Deserialization failure");
            inited_ = false;
        } else {
            inited_ = true;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with CommitPoint::Deserialize.[%s]", e.what());
        assert(false);
    }
}

CommitPoint::CommitPoint(const CommitPoint& src)
        : ec_point_(
          EC_POINT_new(Schnorr::Instance()->curve().group_.get()),
          EC_POINT_clear_free) {
    if (ec_point_ == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        assert(false);
    } else {
        if (EC_POINT_copy(ec_point_.get(), src.ec_point_.get()) != 1) {
            CRYPTO_ERROR("CommitPoint copy failed");
        } else {
            inited_ = true;
        }
    }
}

CommitPoint::~CommitPoint() {}

void CommitPoint::Set(CommitSecret& secret) {
    if (!secret.inited()) {
        CRYPTO_ERROR("Commitment secret value not initialized");
        return;
    }

    if (EC_POINT_mul(
            Schnorr::Instance()->curve().group_.get(),
            ec_point_.get(),
            secret.bignum().get(),
            NULL,
            NULL,
            NULL) != 1) {
        CRYPTO_ERROR("Commit gen failed");
        inited_ = false;
    } else {
        inited_ = true;
    }
}

CommitPoint& CommitPoint::operator=(const CommitPoint& src) {
    inited_ = (EC_POINT_copy(ec_point_.get(), src.ec_point_.get()) == 1);
    return *this;
}

bool CommitPoint::operator==(const CommitPoint& r) const {
    std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        assert(false);
        return false;
    }

    return (inited_ && r.inited_ &&
        (EC_POINT_cmp(
                Schnorr::Instance()->curve().group_.get(),
                ec_point_.get(),
                r.ec_point_.get(),
                ctx.get()) == 0));
}

uint32_t CommitPoint::Serialize(std::string& dst) const {
    assert(inited_);
    SecurityStringTrans::Instance()->EcPointToString(ec_point_, dst);
    return kCommitPointSize;
}

int CommitPoint::Deserialize(const std::string& src) {
    try {
        ec_point_ = SecurityStringTrans::Instance()->StringToEcPoint(src);
        if (ec_point_ == nullptr) {
            CRYPTO_ERROR("Deserialization failure");
            inited_ = false;
        } else {
            inited_ = true;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with CommitPoint::Deserialize.[%s]", e.what());
        return -1;
    }
    return 0;
}

}  // namespace security

}  // namespace lego
