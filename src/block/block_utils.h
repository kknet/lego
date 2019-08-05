#pragma once

#include <memory>

#include "common/utils.h"
#include "common/log.h"

#define BLOCK_DEBUG(fmt, ...) DEBUG("[block]" fmt, ## __VA_ARGS__)
#define BLOCK_INFO(fmt, ...) INFO("[block]" fmt, ## __VA_ARGS__)
#define BLOCK_WARN(fmt, ...) WARN("[block]" fmt, ## __VA_ARGS__)
#define BLOCK_ERROR(fmt, ...) ERROR("[block]" fmt, ## __VA_ARGS__)

namespace lego {

namespace block {

enum BlockErrorCode {
    kBlockSuccess = 0,
    kBlockError = 1,
    kBlockDbNotExists = 2,
    kBlockDbDataInvalid = 3,
};

static const std::string kLastBlockHashPrefix("last_block_hash_pre_");
static inline std::string GetLastBlockHash(uint32_t network_id, uint32_t pool_idx) {
    return (kLastBlockHashPrefix + std::to_string(network_id) + "_" + std::to_string(pool_idx));
}

}  // namespace block

}  // namespace lego
