#include "security/aes.h"

#include <cassert>
#include <openssl/aes.h>

#include "security/crypto_utils.h"

namespace lego {

namespace security {

int Aes::Encrypt(const std::string& src, const std::string& key, std::string& out) {
    assert(key.size() == 16 || key.size() == 24 || key.size() == 25);
    if (src.empty() || key.empty()) {
        return kSecurityError;
    }

    uint8_t iv[AES_BLOCK_SIZE];
    std::fill(iv, iv + AES_BLOCK_SIZE, 0);
    AES_KEY aes;
    if (AES_set_encrypt_key(
            (unsigned char*)key.c_str(),
            key.size() * 8,
            &aes) < 0) {
        return kSecurityError;
    }

    uint32_t out_len = (src.size() / key.size()) * key.size();
    if (src.size() > out_len) {
        out_len += key.size();
    }
    out.resize(src.size(), 0);
    AES_cbc_encrypt(
            (unsigned char*)src.c_str(),
            (unsigned char*)&(out[0]),
            src.size(),
            &aes,
            iv,
            AES_ENCRYPT);
    return kSecuritySuccess;
}

int Aes::Decrypt(const std::string& src, const std::string& key, std::string& out) {
    assert(key.size() == 16 || key.size() == 24 || key.size() == 25);
    if (src.empty() || key.empty()) {
        return kSecurityError;
    }

    uint8_t iv[AES_BLOCK_SIZE];
    std::fill(iv, iv + AES_BLOCK_SIZE, 0);
    AES_KEY aes;
    if (AES_set_decrypt_key(
            (unsigned char*)key.c_str(),
            key.size() * 8,
            &aes) < 0) {
        return kSecurityError;
    }

    out.resize(src.size(), 0);
    AES_cbc_encrypt(
            (unsigned char*)src.c_str(),
            (unsigned char*)&(out[0]),
            src.size(),
            &aes,
            iv,
            AES_DECRYPT);
    return kSecuritySuccess;
}

}  // namespace security

}  // namespace lego