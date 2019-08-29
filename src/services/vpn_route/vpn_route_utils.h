#pragma once

#include "common/utils.h"
#include "common/log.h"

#define VPNROUTE_DEBUG(fmt, ...) DEBUG("[vpnrouteroute]" fmt, ## __VA_ARGS__)
#define VPNROUTE_INFO(fmt, ...) INFO("[vpnrouteroute]" fmt, ## __VA_ARGS__)
#define VPNROUTE_WARN(fmt, ...) WARN("[vpnrouteroute]" fmt, ## __VA_ARGS__)
#define VPNROUTE_ERROR(fmt, ...) ERROR("[vpnrouteroute]" fmt, ## __VA_ARGS__)

namespace lego {

namespace vpnroute {

enum VpnRouteErrorCode {
    kVpnRouteSuccess = 0,
    kVpnRouteError = 1,
};

}  // namespace vpnroute

}  // namespace lego
