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

static const std::vector<std::pair<std::string, uint16_t>> kEncryptTypeVec = {
    std::make_pair<std::string, uint16_t>("bf-cfb", 7453),
    std::make_pair<std::string, uint16_t>("aes-128-cfb",10455),
    std::make_pair<std::string, uint16_t>("aes-192-cfb",6456),
    std::make_pair<std::string, uint16_t>("aes-256-cfb",5457),
    std::make_pair<std::string, uint16_t>("camellia-128-cfb", 4458),
    std::make_pair<std::string, uint16_t>("camellia-192-cfb", 3459),
    std::make_pair<std::string, uint16_t>("camellia-256-cfb", 2460),
    std::make_pair<std::string, uint16_t>("chacha20", 7961),
    std::make_pair<std::string, uint16_t>("chacha20-ietf", 7762),
    std::make_pair<std::string, uint16_t>("rc4-md5", 7963)
};
static const std::string kMode = "tcp_and_udp";

}  // namespace vpn

}  // namespace lego
