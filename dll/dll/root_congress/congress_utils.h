#pragma once

#include "common/utils.h"
#include "common/log.h"

#define CONGRESS_DEBUG(fmt, ...) DEBUG("[congress]" fmt, ## __VA_ARGS__)
#define CONGRESS_INFO(fmt, ...) INFO("[congress]" fmt, ## __VA_ARGS__)
#define CONGRESS_WARN(fmt, ...) WARN("[congress]" fmt, ## __VA_ARGS__)
#define CONGRESS_ERROR(fmt, ...) ERROR("[congress]" fmt, ## __VA_ARGS__)

namespace lego {

namespace congress {

enum CongressErrorCode {
    kCongressSuccess = 0,
    kCongressError = 1,
};

static const uint32_t kCongressTestNetworkShardId = 4u;

}  // namespace congress

}  // namespace lego
