#pragma once

#include "common/utils.h"
#include "common/log.h"

#define INIT_DEBUG(fmt, ...) DEBUG("[init]" fmt, ## __VA_ARGS__)
#define INIT_INFO(fmt, ...) INFO("[init]" fmt, ## __VA_ARGS__)
#define INIT_WARN(fmt, ...) WARN("[init]" fmt, ## __VA_ARGS__)
#define INIT_ERROR(fmt, ...) ERROR("[init]" fmt, ## __VA_ARGS__)

namespace lego {

namespace init {

enum InitErrorCode {
    kInitSuccess = 0,
    kInitError = 1,
};

}  // namespace init

}  // namespace lego
