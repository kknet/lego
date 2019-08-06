#pragma once

#include "security/crypto_utils.h"
#include "security/private_key.h"
#include "security/public_key.h"

namespace lego {

namespace security {

class EcdhCreateKey {
public:
    static EcdhCreateKey* Instance();
    int Init();
    int CreateKey(const PublicKey& peer_pubkey, std::string& sec_key);

private:
    EcdhCreateKey();
    ~EcdhCreateKey();

    EC_KEY *ec_key_{ nullptr };
    int field_size_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(EcdhCreateKey);
};

}  // namespace security

}  // namespace lego
