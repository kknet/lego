#include "security/schnorr.h"

#include <memory.h>

#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ossl_typ.h>

#include "security/curve.h"
#include "security/crypto_utils.h"
#include "security/sha256.h"

#if OPENSSL_VERSION_NUMBER < 0x1010007fL  // only needed before OpenSSL 1.1.0g
#ifdef __cplusplus
extern "C" {
#endif

int BN_generate_dsa_nonce(
        BIGNUM *out,
        const BIGNUM *range,
        const BIGNUM *priv,
        const unsigned char *message,
        size_t message_len,
        BN_CTX *ctx) {
    SHA512_CTX sha;
    unsigned char random_bytes[64];
    unsigned char digest[SHA512_DIGEST_LENGTH];
    unsigned done, todo;
    const unsigned num_k_bytes = BN_num_bytes(range) + 8;
    unsigned char private_bytes[96];
    unsigned char *k_bytes;
    int ret = 0;

    k_bytes = (unsigned char *)OPENSSL_malloc(num_k_bytes);
    if (k_bytes == NULL)
        goto err;

    todo = sizeof(priv->d[0]) * priv->top;
    if (todo > sizeof(private_bytes)) {
        goto err;
    }
    memcpy(private_bytes, priv->d, todo);
    memset(private_bytes + todo, 0, sizeof(private_bytes) - todo);

    for (done = 0; done < num_k_bytes;) {
        if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1)
            goto err;
        SHA512_Init(&sha);
        SHA512_Update(&sha, &done, sizeof(done));
        SHA512_Update(&sha, private_bytes, sizeof(private_bytes));
        SHA512_Update(&sha, message, message_len);
        SHA512_Update(&sha, random_bytes, sizeof(random_bytes));
        SHA512_Final(digest, &sha);

        todo = num_k_bytes - done;
        if (todo > SHA512_DIGEST_LENGTH)
            todo = SHA512_DIGEST_LENGTH;
        memcpy(k_bytes + done, digest, todo);
        done += todo;
    }

    if (!BN_bin2bn(k_bytes, num_k_bytes, out))
        goto err;
    if (BN_mod(out, out, range, ctx) != 1)
        goto err;
    ret = 1;

err:
    OPENSSL_free(k_bytes);
    OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
    return ret;
}
#ifdef __cplusplus
}
#endif

#endif

namespace lego {

namespace security {

Schnorr* Schnorr::Instance() {
    static Schnorr ins;
    return &ins;
}

Schnorr::Schnorr() {}

Schnorr::~Schnorr() {}

void Schnorr::GenPublicKey(PrivateKey& prikey, PublicKey& pubkey) {
    std::lock_guard<std::mutex> guard(schonorr_mutex_);
    pubkey = PublicKey(prikey);
}

bool Schnorr::Sign(
        const std::string& message,
        const PrivateKey& privkey,
        const PublicKey& pubkey,
        Signature& result) {
    std::lock_guard<std::mutex> guard(schonorr_mutex_);
    assert(!message.empty());
    bytes buf(kPublicCompresssedSizeBytes);
    Sha256 sha2;

    bool err = false;
    int res = 1;
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> k(BN_new(), BN_clear_free);
    std::unique_ptr<EC_POINT, void(*)(EC_POINT*)> Q(
            EC_POINT_new(curve_.group_.get()),
            EC_POINT_clear_free);
    std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);

    if ((k != nullptr) && (ctx != nullptr) && (Q != nullptr)) {
        do {
            err = false;
            do {
                err = (BN_generate_dsa_nonce(
                        k.get(),
                        curve_.order_.get(),
                        privkey.bignum().get(),
                        (unsigned char*)message.c_str(),
                        message.size(),
                        ctx.get()) == 0);

                if (err) {
                    CRYPTO_ERROR("Random generation failed");
                    return false;
                }
            } while (BN_is_zero(k.get()));

            err = (EC_POINT_mul(curve_.group_.get(), Q.get(), k.get(), NULL, NULL, NULL) == 0);
            if (err) {
                CRYPTO_ERROR("Commit generation failed");
                return false;
            }

            err = (EC_POINT_point2oct(
                    curve_.group_.get(),
                    Q.get(),
                    POINT_CONVERSION_COMPRESSED,
                    buf.data(),
                    kPublicCompresssedSizeBytes,
                    NULL) != kPublicCompresssedSizeBytes);
            if (err) {
                CRYPTO_ERROR("Commit octet conversion failed");
                return false;
            }

            std::string tmp_buf((char*)buf.data(), buf.size());
            sha2.Update(tmp_buf);
            fill(buf.begin(), buf.end(), 0x00);
            err = (EC_POINT_point2oct(
                    curve_.group_.get(),
                    pubkey.ec_point().get(),
                    POINT_CONVERSION_COMPRESSED,
                    buf.data(),
                    kPublicCompresssedSizeBytes,
                    NULL) != kPublicCompresssedSizeBytes);
            if (err) {
                CRYPTO_ERROR("Pubkey octet conversion failed");
                return false;
            }

            std::string tmp_buf1((char*)buf.data(), buf.size());
            sha2.Update(tmp_buf1);
            sha2.Update(message);
            std::string digest = sha2.Finalize();

            err = ((BN_bin2bn(
                    (unsigned char*)digest.c_str(),
                    digest.size(),
                    result.challenge().get())) == NULL);
            if (err) {
                CRYPTO_ERROR("Digest to challenge failed");
                return false;
            }

            err = (BN_nnmod(
                    result.challenge().get(),
                    result.challenge().get(),
                    curve_.order_.get(),
                    NULL) == 0);
            if (err) {
                CRYPTO_ERROR("BIGNUM NNmod failed");
                return false;
            }

            err = (BN_mod_mul(
                    result.response().get(),
                    result.challenge().get(),
                    privkey.bignum().get(),
                    curve_.order_.get(),
                    ctx.get()) == 0);
            if (err) {
                CRYPTO_ERROR("Response mod mul failed");
                return false;
            }

            err = (BN_mod_sub(
                    result.response().get(),
                    k.get(),
                    result.response().get(),
                    curve_.order_.get(),
                    ctx.get()) == 0);
            if (err) {
                CRYPTO_ERROR("BIGNUM mod sub failed");
                return false;
            }

            fill(buf.begin(), buf.end(), 0x00);
            if (!err) {
                res = (BN_is_zero(result.challenge().get())) ||
                        (BN_is_zero(result.response().get()));
            }

            sha2.Reset();
        } while (res);
    } else {
        CRYPTO_ERROR("Memory allocation failure");
        return false;
    }
    return (res == 0);
}

bool Schnorr::Verify(
        const std::string& message,
        const Signature& toverify,
        const PublicKey& pubkey) {
    std::lock_guard<std::mutex> guard(schonorr_mutex_);
    assert(!message.empty());
    try {
        bytes buf(kPublicCompresssedSizeBytes);
        Sha256 sha2;
        bool err = false;
        bool err2 = false;
        std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> challenge_built(
                BN_new(),
                BN_clear_free);
        std::unique_ptr<EC_POINT, void(*)(EC_POINT*)> Q(
                EC_POINT_new(curve_.group_.get()),
                EC_POINT_clear_free);
        std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);

        if ((challenge_built != nullptr) && (ctx != nullptr) && (Q != nullptr)) {
            err2 = (BN_is_zero(toverify.challenge().get()) ||
                    BN_is_negative(toverify.challenge().get()) ||
                    (BN_cmp(toverify.challenge().get(), curve_.order_.get()) != -1));
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Challenge not in range");
                return false;
            }

            err2 = (BN_is_zero(toverify.response().get()) ||
                    BN_is_negative(toverify.response().get()) ||
                    (BN_cmp(toverify.response().get(), curve_.order_.get()) != -1));
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Response not in range");
                return false;
            }

            err2 = (EC_POINT_mul(
                    curve_.group_.get(),
                    Q.get(),
                    toverify.response().get(),
                    pubkey.ec_point().get(),
                    toverify.challenge().get(),
                    ctx.get()) == 0);
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Commit regenerate failed");
                return false;
            }

            err2 = (EC_POINT_is_at_infinity(curve_.group_.get(), Q.get()));
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Commit at infinity");
                return false;
            }

            err2 = (EC_POINT_point2oct(
                    curve_.group_.get(),
                    Q.get(),
                    POINT_CONVERSION_COMPRESSED,
                    buf.data(),
                    kPublicCompresssedSizeBytes,
                    NULL) != kPublicCompresssedSizeBytes);
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Commit octet conversion failed");
                return false;
            }

            std::string tmp_buf((char*)buf.data(), buf.size());
            sha2.Update(tmp_buf);
            fill(buf.begin(), buf.end(), 0x00);
            err2 = (EC_POINT_point2oct(
                    curve_.group_.get(),
                    pubkey.ec_point().get(),
                    POINT_CONVERSION_COMPRESSED,
                    buf.data(),
                    kPublicCompresssedSizeBytes,
                    NULL) != kPublicCompresssedSizeBytes);
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Pubkey octet conversion failed");
                return false;
            }

            std::string tmp_buf1((char*)buf.data(), buf.size());
            sha2.Update(tmp_buf1);
            sha2.Update(message);
            std::string digest = sha2.Finalize();

            err2 = (BN_bin2bn(
                    (unsigned char*)(digest.c_str()),
                    digest.size(),
                    challenge_built.get()) == NULL);
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Challenge bin2bn conversion failed");
                return false;
            }

            err2 = (BN_nnmod(
                    challenge_built.get(),
                    challenge_built.get(),
                    curve_.order_.get(), NULL) == 0);
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Challenge rebuild mod failed");
                return false;
            }

            sha2.Reset();
        } else {
            CRYPTO_ERROR("Memory allocation failure");
            return false;
        }
        return (!err) && (BN_cmp(challenge_built.get(), toverify.challenge().get()) == 0);
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with Schnorr::Verify.[%s]", e.what());
        return false;
    }
}

}  // namespace security

}  // namespace lego
