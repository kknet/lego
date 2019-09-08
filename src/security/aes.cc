#include "security/aes.h"

#include <cassert>
#include <openssl/aes.h>

#include "security/crypto_utils.h"

namespace lego {

namespace security {

int Aes::Encrypt(const std::string& src, const std::string& key, std::string& out) {
    assert(key.size() == 16 || key.size() == 24 || key.size() == 32);
    if (src.empty() || key.empty()) {
        return kSecurityError;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    std::fill(iv, iv + AES_BLOCK_SIZE, 0);
    AES_KEY aes;
    if (AES_set_encrypt_key(
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
            AES_ENCRYPT);
    return kSecuritySuccess;
}

int Aes::Decrypt(const std::string& src, const std::string& key, std::string& out) {
    assert(key.size() == 16 || key.size() == 24 || key.size() == 32);
    if (src.empty() || key.empty()) {
        return kSecurityError;
    }

    unsigned char iv[AES_BLOCK_SIZE];
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

int Aes::Encrypt(char* str_in, int len, char* key, int key_len, char* out) {
    assert(key_len == 16 || key_len == 24 || key_len == 32);
    if (!str_in || !key || !out || len <= 0 || key_len <= 0) {
        return kSecurityError;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    std::fill(iv, iv + AES_BLOCK_SIZE, 0);
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char*)key, key_len * 8, &aes) < 0) {
        return kSecurityError;
    }

    AES_cbc_encrypt((unsigned char*)str_in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
    return kSecuritySuccess;
}

int Aes::Decrypt(char* str_in, int len, char* key, int key_len, char* out) {
    assert(key_len == 16 || key_len == 24 || key_len == 32);
    if (!str_in || !key || !out || len <= 0 || key_len <= 0) {
        return kSecurityError;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    std::fill(iv, iv + AES_BLOCK_SIZE, 0);

    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char*)key, key_len * 8, &aes) < 0) {
        return kSecurityError;
    }

    AES_cbc_encrypt((unsigned char*)str_in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
    return kSecuritySuccess;
}

}  // namespace security

}  // namespace lego