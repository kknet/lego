#pragma once

#include <memory>
#include <atomic>

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

struct AccountInfo {
    AccountInfo(const std::string& acc, int64_t b, uint64_t h)
        : account_id(acc), balance(b), height(h) {}
    std::string account_id;
    int64_t balance;
    uint64_t height;
    std::atomic<uint32_t> out_count{ 0 };
    std::atomic<uint32_t> in_count{ 0 };
    std::atomic<uint64_t> out_lego{ 0 };
    std::atomic<uint64_t> in_lego{ 0 };
    uint32_t new_height{ 0 };
};
typedef std::shared_ptr<AccountInfo> AccountInfoPtr;

static const std::string kLastBlockHashPrefix("last_block_hash_pre_");
static inline std::string GetLastBlockHash(uint32_t network_id, uint32_t pool_idx) {
    return (kLastBlockHashPrefix + std::to_string(network_id) + "_" + std::to_string(pool_idx));
}

}  // namespace block

}  // namespace lego
