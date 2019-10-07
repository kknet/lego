#pragma once

#include "security/crypto_utils.h"

namespace lego {

namespace security {

class Aes {
public:
    static int Encrypt(const std::string& src, const std::string& key, std::string& out);
    static int Decrypt(const std::string& src, const std::string& key, std::string& out);
    static int Encrypt(char* str_in, int len, char* key, int key_len, char* out);
    static int Decrypt(char* str_in, int len, char* key, int key_len, char* out);
    static int CfbEncrypt(char* str_in, int len, char* key, int key_len, char* out);
    static int CfbDecrypt(char* str_in, int len, char* key, int key_len, char* out);

private:
    Aes();
    ~Aes();
    DISALLOW_COPY_AND_ASSIGN(Aes);
};

}  // namespace security

}  // namespace lego
