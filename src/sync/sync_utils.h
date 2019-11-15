#pragma once

#include "common/utils.h"
#include "common/log.h"

#define SYNC_DEBUG(fmt, ...) DEBUG("[SYNC]" fmt, ## __VA_ARGS__)
#define SYNC_INFO(fmt, ...) INFO("[SYNC]" fmt, ## __VA_ARGS__)
#define SYNC_WARN(fmt, ...) WARN("[SYNC]" fmt, ## __VA_ARGS__)
#define SYNC_ERROR(fmt, ...) ERROR("[SYNC]" fmt, ## __VA_ARGS__)

namespace lego {

namespace sync {

enum SyncErrorCode {
    kSyncSuccess = 0,
    kSyncError = 1,
    kSyncKeyExsits = 2,
    kSyncKeyAdded = 3,
};

enum SyncPriorityType {
    kSyncPriLowest = 0,
    kSyncPriLow = 1,
    kSyncNormal = 2,
    kSyncHigh = 3,
    kSyncHighest = 4,
};

static const uint32_t kSyncValueRetryPeriod = 3 * 1000 * 1000u;  // Persist 3s
static const uint32_t kTimeoutCheckPeriod = 3 * 1000 * 1000u;  // Persist 3s
static const uint32_t kMaxSyncMapCapacity = 1000000u;
static const uint32_t kMaxSyncKeyCount = 256u;
static const uint32_t kSyncNeighborCount = 3u;
static const uint32_t kSyncTickPeriod = 3u * 1000u * 1000u;
static const uint32_t kSyncPacketMaxSize = 5u * 1024u;  // 5k for test(later rudp to 1M)
static const uint32_t kSyncMaxKeyCount = 10000u;  // 10k
static const uint32_t kSyncMaxRetryTimes = 3u;  // fail retry 3 times

}  // namespace sync

}  // namespace lego
