#pragma once

#include <limits>

#include "common/utils.h"
#include "common/log.h"

#define CLIENT_DEBUG(fmt, ...) DEBUG("[client]" fmt, ## __VA_ARGS__)
#define CLIENT_INFO(fmt, ...) INFO("[client]" fmt, ## __VA_ARGS__)
#define CLIENT_WARN(fmt, ...) WARN("[client]" fmt, ## __VA_ARGS__)
#define CLIENT_ERROR(fmt, ...) ERROR("[client]" fmt, ## __VA_ARGS__)

namespace lego {

namespace client {

enum InitErrorCode {
    kClientSuccess = 0,
    kClientError = 1,
};

enum BftStatus {
    kBftInit = 0,
};

static const uint32_t kBftBroadcastIgnBloomfilterHop = 1u;
static const uint32_t kBftBroadcastStopTimes = 2u;
static const uint32_t kBftHopLimit = 5u;
static const uint32_t kBftHopToLayer = 2u;
static const uint32_t kBftNeighborCount = 7u;
static const int64_t kInvalidTimestamp = (std::numeric_limits<int64_t>::max)();
static const std::string kTransactionPbftAddress("Transaction");

}  // namespace client

}  // namespace lego
