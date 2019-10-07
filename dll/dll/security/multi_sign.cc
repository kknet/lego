#include "stdafx.h"
#include "security/multi_sign.h"

#include "security/schnorr.h"
#include "security/crypto_utils.h"
#include "security/sha256.h"

namespace lego {

namespace security {

MultiSign* MultiSign::Instance() {
    static MultiSign sign;
    return &sign;
}

std::shared_ptr<PublicKey> MultiSign::AggregatePubKeys(
        const std::vector<PublicKey>& pubkeys) {
    const Curve& curve = Schnorr::Instance()->curve();
    if (pubkeys.empty()) {
        CRYPTO_ERROR("Empty list of public keys");
        return nullptr;
    }

    std::shared_ptr<PublicKey> agg_pubkey(new PublicKey(pubkeys.at(0)));
    if (agg_pubkey == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        return nullptr;
    }

    for (unsigned int i = 1; i < pubkeys.size(); i++) {
        if (EC_POINT_add(
                curve.group_.get(),
                agg_pubkey->ec_point().get(),
                agg_pubkey->ec_point().get(),
                pubkeys.at(i).ec_point().get(),
                NULL) == 0) {
            CRYPTO_ERROR("Pubkey aggregation failed");
            return nullptr;
        }
    }
    return agg_pubkey;
}

std::shared_ptr<CommitPoint> MultiSign::AggregateCommits(
        const std::vector<CommitPoint>& commit_points) {
    const Curve& curve = Schnorr::Instance()->curve();
    if (commit_points.empty()) {
        CRYPTO_ERROR("Empty list of commits");
        return nullptr;
    }

    std::shared_ptr<CommitPoint> agg_commit(new CommitPoint(commit_points.at(0)));
    if (agg_commit == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        assert(false);
        return nullptr;
    }

    for (unsigned int i = 1; i < commit_points.size(); i++) {
        if (EC_POINT_add(curve.group_.get(), agg_commit->ec_point().get(),
            agg_commit->ec_point().get(), commit_points.at(i).ec_point().get(),
            NULL) == 0) {
            CRYPTO_ERROR("Commit aggregation failed");
            return nullptr;
        }
    }
    return agg_commit;
}

std::shared_ptr<Response> MultiSign::AggregateResponses(
        const std::vector<Response>& responses) {
    const Curve& curve = Schnorr::Instance()->curve();
    if (responses.size() == 0) {
        CRYPTO_ERROR("Empty list of responses");
        return nullptr;
    }

    std::shared_ptr<Response> agg_response(new Response(responses.at(0)));
    if (agg_response == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        assert(false);
        return nullptr;
    }

    std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        assert(false);
        return nullptr;
    }

    for (unsigned int i = 1; i < responses.size(); i++) {
        if (BN_mod_add(
                agg_response->bignum().get(),
                agg_response->bignum().get(),
                responses.at(i).bignum().get(),
                curve.order_.get(),
                ctx.get()) == 0) {
            CRYPTO_ERROR("Response aggregation failed");
            return nullptr;
        }
    }
    return agg_response;
}

std::shared_ptr<Signature> MultiSign::AggregateSign(
        const Challenge& challenge,
        const Response& agg_response) {
    if (!challenge.inited()) {
        CRYPTO_ERROR("Challenge not initialized");
        return nullptr;
    }

    if (!agg_response.inited()) {
        CRYPTO_ERROR("Response not initialized");
        return nullptr;
    }

    std::shared_ptr<Signature> result(new Signature());
    if (result == nullptr) {
        CRYPTO_ERROR("Memory allocation failure");
        assert(false);
        return nullptr;
    }

    if (BN_copy(result->challenge().get(), challenge.bignum().get()) == NULL) {
        CRYPTO_ERROR("Signature generation (copy challenge) failed");
        return nullptr;
    }

    if (BN_copy(result->response().get(), agg_response.bignum().get()) == NULL) {
        CRYPTO_ERROR("Signature generation (copy response) failed");
        return nullptr;
    }
    return result;
}

bool MultiSign::VerifyResponse(
        const Response& response,
        const Challenge& challenge,
        const PublicKey& pubkey,
        const CommitPoint& commit_point) {
    try {
        if (!response.inited()) {
           CRYPTO_ERROR("Response not initialized");
            return false;
        }

        if (!challenge.inited()) {
           CRYPTO_ERROR("Challenge not initialized");
            return false;
        }

        if (!commit_point.inited()) {
           CRYPTO_ERROR("Commit point not initialized");
            return false;
        }

        const Curve& curve = Schnorr::Instance()->curve();
        bool err = false;
        std::unique_ptr<EC_POINT, void(*)(EC_POINT*)> Q(
                EC_POINT_new(curve.group_.get()),
                EC_POINT_clear_free);
        std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);

        if ((ctx != nullptr) && (Q != nullptr)) {
            err = (BN_is_zero(response.bignum().get()) ||
                    (BN_cmp(response.bignum().get(), curve.order_.get()) != -1));
            if (err) {
               CRYPTO_ERROR("Response not in range");
                return false;
            }

            err = (EC_POINT_mul(
                    curve.group_.get(),
                    Q.get(),
                    response.bignum().get(),
                    pubkey.ec_point().get(),
                    challenge.bignum().get(),
                    ctx.get()) == 0);
            if (err) {
               CRYPTO_ERROR("Commit regenerate failed");
                return false;
            }

            err = (EC_POINT_cmp(curve.group_.get(), Q.get(), commit_point.ec_point().get(),
                ctx.get()) != 0);
            if (err) {
                CRYPTO_ERROR("Generated commit point doesn't match the given one");
                return false;
            }
        } else {
            CRYPTO_ERROR("Memory allocation failure");
            assert(false);
            return false;
        }
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with MultiSig::VerifyResponse.[%s]", e.what());
        return false;
    }
    return true;
}

bool MultiSign::MultiSigVerify(
        const std::string& message,
        const Signature& toverify,
        const PublicKey& pubkey) {
    std::lock_guard<std::mutex> guard(multi_sign_mutex_);
    assert(!message.empty());
    try {
        Sha256 sha2;
        std::string tmp_func_byte((char)kThirdHashFunctionByte, 1);
        sha2.Update(tmp_func_byte);
        bytes buf(kPublicCompresssedSizeBytes);
        bool err = false;
        bool err2 = false;
        const Curve& curve = Schnorr::Instance()->curve();
        std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> challenge_built(BN_new(), BN_clear_free);
        std::unique_ptr<EC_POINT, void(*)(EC_POINT*)> Q(
                EC_POINT_new(curve.group_.get()),
                EC_POINT_clear_free);
        std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);

        if ((challenge_built != nullptr) && (ctx != nullptr) && (Q != nullptr)) {
            err2 = (BN_is_zero(toverify.challenge().get()) ||
                    BN_is_negative(toverify.challenge().get()) ||
                    (BN_cmp(toverify.challenge().get(), curve.order_.get()) != -1));
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Challenge not in range");
                return false;
            }

            err2 = (BN_is_zero(toverify.response().get()) ||
                    BN_is_negative(toverify.response().get()) ||
                    (BN_cmp(toverify.response().get(), curve.order_.get()) != -1));
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Response not in range");
                return false;
            }

            err2 = (EC_POINT_mul(
                    curve.group_.get(),
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

            err2 = (EC_POINT_is_at_infinity(curve.group_.get(), Q.get()));
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Commit at infinity");
                return false;
            }

            err2 = (EC_POINT_point2oct(
                    curve.group_.get(),
                    Q.get(),
                    POINT_CONVERSION_COMPRESSED, buf.data(),
                    kPublicCompresssedSizeBytes, NULL) != kPublicCompresssedSizeBytes);
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Commit octet conversion failed");
                return false;
            }

            std::string tmp_buf1((char*)buf.data(), buf.size());
            sha2.Update(tmp_buf1);
            fill(buf.begin(), buf.end(), 0x00);
            err2 = (EC_POINT_point2oct(
                    curve.group_.get(),
                    pubkey.ec_point().get(),
                    POINT_CONVERSION_COMPRESSED,
                    buf.data(),
                    kPublicCompresssedSizeBytes, NULL) != kPublicCompresssedSizeBytes);
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Pubkey octet conversion failed");
                return false;
            }

            std::string tmp_buf2((char*)buf.data(), buf.size());
            sha2.Update(tmp_buf2);
            sha2.Update(message);
            std::string digest = sha2.Finalize();
            err2 = (BN_bin2bn(
                    (unsigned char*)digest.c_str(),
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
                    curve.order_.get(),
                    NULL) == 0);
            err = err || err2;
            if (err2) {
                CRYPTO_ERROR("Challenge rebuild mod failed");
                return false;
            }

            sha2.Reset();
        } else {
            CRYPTO_ERROR("Memory allocation failure");
            assert(false);
            return false;
        }
        return (!err) && (BN_cmp(challenge_built.get(), toverify.challenge().get()) == 0);
    } catch (const std::exception& e) {
        CRYPTO_ERROR("Error with Schnorr::Verify.[%s]", e.what());
        return false;
    }
}

bool MultiSign::SignKey(
        const std::string& message_with_pubkey,
        const PublicKey& pub_key,
        const PrivateKey& pri_key,
        Signature& signature) {
    return Schnorr::Instance()->Sign(message_with_pubkey, pri_key, pub_key, signature);
}

bool MultiSign::VerifyKey(
        const std::string& message_with_pubkey,
        const Signature& signature,
        const PublicKey& pub_key) {
    return Schnorr::Instance()->Verify(message_with_pubkey, signature, pub_key);
}

}  // namespace security

}  // namespace lego
