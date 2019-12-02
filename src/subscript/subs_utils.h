#pragma once

#include "common/utils.h"
#include "common/log.h"

#define SUBS_DEBUG(fmt, ...) DEBUG("[SUBS]" fmt, ## __VA_ARGS__)
#define SUBS_INFO(fmt, ...) INFO("[SUBS]" fmt, ## __VA_ARGS__)
#define SUBS_WARN(fmt, ...) WARN("[SUBS]" fmt, ## __VA_ARGS__)
#define SUBS_ERROR(fmt, ...) ERROR("[SUBS]" fmt, ## __VA_ARGS__)

namespace lego {

namespace subs {

enum SubsErrorCode {
    kSubsSuccess = 0,
    kSubsError = 1,
};

}  // namespace subs

}  // namespace lego
