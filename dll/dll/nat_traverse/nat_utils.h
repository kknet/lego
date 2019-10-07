#pragma once

#include "common/utils.h"
#include "common/log.h"

#define NAT_DEBUG(fmt, ...) DEBUG("[nat]" fmt, ## __VA_ARGS__)
#define NAT_INFO(fmt, ...) INFO("[nat]" fmt, ## __VA_ARGS__)
#define NAT_WARN(fmt, ...) WARN("[nat]" fmt, ## __VA_ARGS__)
#define NAT_ERROR(fmt, ...) ERROR("[nat]" fmt, ## __VA_ARGS__)
