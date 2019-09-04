#pragma once

#include "common/utils.h"
#include "common/log.h"

#define VPNSVR_DEBUG(fmt, ...) DEBUG("[vpn_svr]" fmt, ## __VA_ARGS__)
#define VPNSVR_INFO(fmt, ...) INFO("[vpn_svr]" fmt, ## __VA_ARGS__)
#define VPNSVR_WARN(fmt, ...) WARN("[vpn_svr]" fmt, ## __VA_ARGS__)
#define VPNSVR_ERROR(fmt, ...) ERROR("[vpn_svr]" fmt, ## __VA_ARGS__)

namespace lego {

namespace vpn {

enum VpnSvrErrorCode {
    kVpnsvrSuccess = 0,
    kVpnsvrError = 1,
};

}  // namespace vpn

}  // namespace lego
