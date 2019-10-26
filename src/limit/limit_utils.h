#pragma once

#include "common/log.h"

#define LIMIT_DEBUG(fmt, ...) DEBUG("[limit]" fmt, ## __VA_ARGS__)
#define LIMIT_INFO(fmt, ...) INFO("[limit]" fmt, ## __VA_ARGS__)
#define LIMIT_WARN(fmt, ...) WARN("[limit]" fmt, ## __VA_ARGS__)
#define LIMIT_ERROR(fmt, ...) ERROR("[limit]" fmt, ## __VA_ARGS__)

namespace lego {

namespace limit {

enum LimitErrorCode {
    kLimitSuccess = 0,
    kLimitError = 1,
};

}  // namespace limit

}  // namespace lego
