#pragma once

#include "services/vpn_server/vpn_svr_utils.h"

struct listen_ctx_t;

namespace lego {

namespace vpn {

class VpnServer {
public:
    VpnServer();
    ~VpnServer();
    int Init(
            const std::string& ip,
            uint16_t port,
            const std::string& passwd,
            const std::string& key,
            const std::string& method);

private:
    listen_ctx_t listen_ctx_;
    DISALLOW_COPY_AND_ASSIGN(VpnServer);
};

}  // namespace vpn

}  // namespace lego
