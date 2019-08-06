#pragma once

#include "security/crypto_utils.h"

namespace lego {

namespace security {

class Aes {
public:
    static int Encrypt(const std::string& src, const std::string& key, std::string& out);
    static int Decrypt(const std::string& src, const std::string& key, std::string& out);

private:
    Aes();
    ~Aes();
    DISALLOW_COPY_AND_ASSIGN(Aes);
};

}  // namespace security

}  // namespace lego
