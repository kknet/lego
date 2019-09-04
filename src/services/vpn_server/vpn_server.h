#pragma once

#include "services/vpn_server/vpn_svr_utils.h"

namespace lego {

namespace vpn {

class VpnServer {
public:
    VpnServer();
    ~VpnServer();
    int Init();

private:

    DISALLOW_COPY_AND_ASSIGN(VpnServer);
};

}  // namespace vpn

}  // namespace lego
