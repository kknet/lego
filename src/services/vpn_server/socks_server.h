#pragma once

#include "services/vpn_server/vpn_svr_utils.h"

namespace lego {

namespace vpn {

class SocksServer {
public:
    SocksServer();
    ~SocksServer();

private:

    DISALLOW_COPY_AND_ASSIGN(SocksServer);
};

}  // namespace vpn

}  // namespace lego
