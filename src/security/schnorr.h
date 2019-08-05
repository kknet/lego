#pragma once

#include <mutex>
#include <iostream>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "common/utils.h"
#include "common/encode.h"
#include "security/private_key.h"
#include "security/public_key.h"
#include "security/curve.h"
#include "security/signature.h"

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
        BN_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif

namespace lego {

namespace security {

class Schnorr {
public:
    static Schnorr* Instance();
    void GenPublicKey(PrivateKey& prikey, PublicKey& pubkey);
    bool Sign(
            const std::string& message,
            const PrivateKey& privkey,
            const PublicKey& pubkey,
            Signature& result);
    bool Verify(
            const std::string& message,
            const Signature& toverify,
            const PublicKey& pubkey);

    const Curve& curve() const {
        return curve_;
    }

    void set_prikey(const std::shared_ptr<PrivateKey>& prikey) {
        prikey_ptr_ = prikey;
        prikey_ptr_->Serialize(str_prikey_);
    }

    void set_pubkey(const std::shared_ptr<PublicKey>& pubkey) {
        pubkey_ptr_ = pubkey;
        pubkey_ptr_->Serialize(str_pubkey_);
    }

    const std::shared_ptr<PrivateKey>& prikey() const {
        return prikey_ptr_;
    }

    const std::shared_ptr<PublicKey>& pubkey() const {
        return pubkey_ptr_;
    }

    const std::string& str_prikey() const {
        return str_prikey_;
    }

    const std::string& str_pubkey() const {
        return str_pubkey_;
    }

private:
    Schnorr();
    ~Schnorr();

    Curve curve_;
    std::mutex schonorr_mutex_;
    std::shared_ptr<PrivateKey> prikey_ptr_{ nullptr };
    std::shared_ptr<PublicKey> pubkey_ptr_{ nullptr };
    std::string str_prikey_;
    std::string str_pubkey_;

    DISALLOW_COPY_AND_ASSIGN(Schnorr);
};

}  // namespace security

}  // namespace lego
