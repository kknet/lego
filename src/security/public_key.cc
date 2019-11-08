#include "stdafx.h"
#include "security/public_key.h"

#include "common/encode.h"
#include "security/schnorr.h"
#include "security/crypto_utils.h"
#include "security/security_string_trans.h"

namespace lego {

namespace security {

PublicKey::PublicKey()
        : ec_point_(
            EC_POINT_new(Schnorr::Instance()->curve().group_.get()),
            EC_POINT_clear_free) {
    assert(ec_point_ != nullptr);
}

PublicKey::PublicKey(PrivateKey& privkey)
        : ec_point_(
            EC_POINT_new(Schnorr::Instance()->curve().group_.get()),
            EC_POINT_clear_free) {
    assert(ec_point_ != nullptr);
    const Curve& curve = Schnorr::Instance()->curve();
    if (BN_is_zero(privkey.bignum().get()) ||
            (BN_cmp(privkey.bignum().get(), curve.order_.get()) != -1)) {
        CRYPTO_ERROR("Input private key is invalid. Public key "
                "generation failed");
        return;
    }

    if (EC_POINT_mul(
            curve.group_.get(),
            ec_point_.get(),
            privkey.bignum().get(),
            NULL,
            NULL,
            NULL) == 0) {
        CRYPTO_ERROR("Public key generation failed");
        return;
    }
}

PublicKey::PublicKey(const std::string& src) {
    ec_point_ = SecurityStringTrans::Instance()->StringToEcPoint(src);
    assert(ec_point_ != nullptr);
}

PublicKey::PublicKey(const PublicKey& src)
        : ec_point_(
            EC_POINT_new(Schnorr::Instance()->curve().group_.get()),
            EC_POINT_clear_free) {
    assert(ec_point_ != nullptr);
    if (EC_POINT_copy(ec_point_.get(), src.ec_point_.get()) != 1) {
        CRYPTO_ERROR("copy ec point failed!");
        assert(false);
    }
}

PublicKey::~PublicKey() {}

PublicKey& PublicKey::operator=(const PublicKey& src) {
    if (EC_POINT_copy(ec_point_.get(), src.ec_point_.get()) != 1) {
        CRYPTO_ERROR("PubKey copy failed");
        assert(false);
    }
    return *this;

}

bool PublicKey::operator<(const PublicKey& r) const {
    std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        return false;
    }

    std::shared_ptr<BIGNUM> lhs_bnvalue;
    lhs_bnvalue.reset(
            EC_POINT_point2bn(
                    Schnorr::Instance()->curve().group_.get(),
                    ec_point_.get(),
                    POINT_CONVERSION_COMPRESSED,
                    NULL,
                    ctx.get()),
            BN_clear_free);
    std::shared_ptr<BIGNUM> rhs_bnvalue;
    rhs_bnvalue.reset(
            EC_POINT_point2bn(
                    Schnorr::Instance()->curve().group_.get(),
                    r.ec_point_.get(),
                    POINT_CONVERSION_COMPRESSED,
                    NULL,
                    ctx.get()),
            BN_clear_free);

    if ((lhs_bnvalue == nullptr) || (rhs_bnvalue == nullptr)) {
        CRYPTO_ERROR("Memory allocation failure");
        return false;
    }

    if (BN_cmp(lhs_bnvalue.get(), rhs_bnvalue.get()) == -1) {
        return true;
    }
    return false;
}

bool PublicKey::operator>(const PublicKey& r) const {
    return r < *this;
}

bool PublicKey::operator==(const PublicKey& r) const {
std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        return false;
    }

    std::shared_ptr<BIGNUM> lhs_bnvalue;
    lhs_bnvalue.reset(
            EC_POINT_point2bn(
                    Schnorr::Instance()->curve().group_.get(),
                    ec_point_.get(),
                    POINT_CONVERSION_COMPRESSED,
                    NULL,
                    ctx.get()),
            BN_clear_free);
    std::shared_ptr<BIGNUM> rhs_bnvalue;
    rhs_bnvalue.reset(
            EC_POINT_point2bn(
                    Schnorr::Instance()->curve().group_.get(),
                    r.ec_point_.get(),
                    POINT_CONVERSION_COMPRESSED,
                    NULL,
                    ctx.get()),
            BN_clear_free);

    if ((lhs_bnvalue == nullptr) || (rhs_bnvalue == nullptr)) {
        CRYPTO_ERROR("Memory allocation failure");
        return false;
    }

    if (BN_cmp(lhs_bnvalue.get(), rhs_bnvalue.get()) == 0) {
        return true;
    }
    return false;
}

PublicKey PublicKey::GetPubKeyFromString(const std::string& key) {
    assert(key.size() == 66);
    return PublicKey(key);
}

uint32_t PublicKey::Serialize(std::string& dst) const {
    SecurityStringTrans::Instance()->EcPointToString(ec_point_, dst);
    return kPublicKeySize;
}

int PublicKey::Deserialize(const std::string& src) {
    std::shared_ptr<EC_POINT> result = SecurityStringTrans::Instance()->StringToEcPoint(src);
    if (result == nullptr) {
        CRYPTO_ERROR("ECPOINTSerialize::GetNumber failed[%s]",
                common::Encode::HexEncode(src).c_str());
        return -1;
    }

    if (!EC_POINT_copy(ec_point_.get(), result.get())) {
        CRYPTO_ERROR("PubKey copy failed");
        return -1;
    }
    return 0;
}

}  // namespace security

}  // namespace lego
