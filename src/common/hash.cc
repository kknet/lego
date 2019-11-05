#include "stdafx.h"
#include "common/hash.h"

#include <string.h>

#include "common/log.h"
#include "common/encode.h"
#include "xxHash/xxhash.h"
#include "security/sha256.h"

namespace lego {

namespace common {

union Hash128Union {
    Hash128Union() {
        memset(str, 0, sizeof(str));
    }

    struct {
        uint64_t h;
        uint64_t l;
    } u128;
    char str[16];
};

union Hash192Union {
    Hash192Union() {
        memset(str, 0, sizeof(str));
    }

    struct {
        uint64_t a;
        uint64_t b;
        uint64_t c;
    } u192;
    char str[24];
};

union Hash256Union {
    Hash256Union() {
        memset(str, 0, sizeof(str));
    }

    struct {
        uint64_t a;
        uint64_t b;
        uint64_t c;
        uint64_t d;
    } u256;
    char str[32];
};

uint32_t Hash::Hash32(const std::string& str) {
    return XXH32(str.c_str(), str.size(), kHashSeedU32);
}

uint64_t Hash::Hash64(const std::string& str) {
    return XXH64(str.c_str(), str.size(), kHashSeed1);
}

std::string Hash::Hash128(const std::string& str) {
    Hash128Union hash;
    hash.u128.h = XXH64(str.c_str(), str.size(), kHashSeed1);
    hash.u128.l = XXH64(str.c_str(), str.size(), kHashSeed2);
    return std::string(hash.str, sizeof(hash.str));
}

std::string Hash::Hash256(const std::string& str) {
    Hash256Union hash;
    hash.u256.a = XXH64(str.c_str(), str.size(), kHashSeed1);
    hash.u256.b = XXH64(str.c_str(), str.size(), kHashSeed2);
    hash.u256.c = XXH64(str.c_str(), str.size(), kHashSeed3);
    hash.u256.d = XXH64(str.c_str(), str.size(), kHashSeed4);
    return std::string(hash.str, sizeof(hash.str));
}

std::string Hash::Hash192(const std::string& str) {
    Hash192Union hash;
    hash.u192.a = XXH64(str.c_str(), str.size(), kHashSeed1);
    hash.u192.b = XXH64(str.c_str(), str.size(), kHashSeed2);
    hash.u192.c = XXH64(str.c_str(), str.size(), kHashSeed3);
    return std::string(hash.str, sizeof(hash.str));
}

std::string Hash::Sha256(const std::string& str) {
    security::Sha256 sha256;
    sha256.Update(str);
    return sha256.Finalize();
}

}  // namespace common

}  // namespace lego
