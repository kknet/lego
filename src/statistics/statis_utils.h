#pragma once

#include "common/utils.h"
#include "common/log.h"

#define STATIS_DEBUG(fmt, ...) DEBUG("[statis]" fmt, ## __VA_ARGS__)
#define STATIS_INFO(fmt, ...) INFO("[statis]" fmt, ## __VA_ARGS__)
#define STATIS_WARN(fmt, ...) WARN("[statis]" fmt, ## __VA_ARGS__)
#define STATIS_ERROR(fmt, ...) ERROR("[statis]" fmt, ## __VA_ARGS__)

namespace lego {

namespace statis {

enum StatisErrorCode {
    kStatisSuccess = 0,
    kStatisError = 1,
};

}  // namespace statis

}  // namespace lego
