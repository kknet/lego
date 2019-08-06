#pragma once

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

}  // namespace client

}  // namespace lego
