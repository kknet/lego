#pragma once

#include "common/utils.h"
#include "common/log.h"

#define DHT_DEBUG(fmt, ...) DEBUG("[dht]" fmt, ## __VA_ARGS__)
#define DHT_INFO(fmt, ...) INFO("[dht]" fmt, ## __VA_ARGS__)
#define DHT_WARN(fmt, ...) WARN("[dht]" fmt, ## __VA_ARGS__)
#define DHT_ERROR(fmt, ...) ERROR("[dht]" fmt, ## __VA_ARGS__)

namespace lego {

namespace dht {

enum DhtErrorCode {
    kDhtSuccess = 0,
    kDhtError = 1,
    kDhtInvalidNat = 2,
    kDhtNodeJoined = 3,
    kDhtInvalidBucket = 4,
    kDhtDesInvalid = 5,
};

static const uint32_t kDhtNearestNodesCount = 16u;
static const uint32_t kDhtMinReserveNodes = 4u;
static const uint32_t kDhtKeySize = 32u;
static const uint32_t kDhtMaxNeighbors = kDhtKeySize * 8 + kDhtNearestNodesCount;
static const uint32_t kRefreshNeighborsCount = 64u;
static const uint32_t kRefreshNeighborsDefaultCount = 64u;
static const uint32_t kRefreshNeighborsBloomfilterBitCount = 4096u;
static const uint32_t kRefreshNeighborsBloomfilterHashCount = 11u;
static const uint32_t kHeartbeatDefaultAliveTimes = 7u;

}  // namespace dht

}  // namespace lego
