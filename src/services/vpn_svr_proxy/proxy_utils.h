#pragma once

#include "common/utils.h"
#include "common/log.h"

#define PROXY_DEBUG(fmt, ...) DEBUG("[proxy]" fmt, ## __VA_ARGS__)
#define PROXY_INFO(fmt, ...) INFO("[proxy]" fmt, ## __VA_ARGS__)
#define PROXY_WARN(fmt, ...) WARN("[proxy]" fmt, ## __VA_ARGS__)
#define PROXY_ERROR(fmt, ...) ERROR("[proxy]" fmt, ## __VA_ARGS__)

namespace lego {

namespace vpn {

enum InitErrorCode {
    kProxySuccess = 0,
    kProxyError = 1,
};

static const std::vector<std::string> kEncryptTypeVec = {
    "bf-cfb", "seed-cfb", "aes-128-cfb","aes-192-cfb", "aes-256-cfb",
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "chacha20",
    "chacha20-ietf", "rc4-md5" };
static const std::pair<uint16_t, uint16_t> kPortRange(1024, 65535);
static const std::string kMode = "tcp_and_udp";

}  // namespace vpn

}  // namespace lego
