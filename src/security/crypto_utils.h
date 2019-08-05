#pragma once

#include <memory>
#include <vector>

#include "common/utils.h"
#include "common/log.h"

#define CRYPTO_DEBUG(fmt, ...) DEBUG("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_INFO(fmt, ...) INFO("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_WARN(fmt, ...) WARN("[crypto]" fmt, ## __VA_ARGS__)
#define CRYPTO_ERROR(fmt, ...) ERROR("[crypto]" fmt, ## __VA_ARGS__)

namespace lego {

namespace security {

typedef std::vector<uint8_t> bytes;
static const uint32_t kPublicCompresssedSizeBytes = 33u;
static const uint32_t kCommitPointHashSize = 32u;
static const uint32_t kChallengeSize = 32u;
static const uint32_t kResponseSize = 32u;
static const uint8_t kSecondHashFunctionByte = 0x01;
static const uint8_t kThirdHashFunctionByte = 0x11;
static const uint32_t kCommitSecretSize = 32u;
static const uint32_t kCommitPointSize = 33u;
static const uint32_t kPrivateKeySize = 32u;
static const uint32_t kPublicKeySize = 33u;

}  // namespace security

}  // namespace lego
