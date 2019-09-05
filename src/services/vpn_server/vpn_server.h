#pragma once

#include <thread>
#include <memory>

#include "services/vpn_server/vpn_svr_utils.h"

namespace lego {

namespace vpn {

class VpnServer {
public:
    static int Init(
            const std::string& ip,
            uint16_t port,
            const std::string& passwd,
            const std::string& key,
            const std::string& method);
    static int ParserReceivePacket(const char* buf);

private:
    VpnServer();
    ~VpnServer();

    DISALLOW_COPY_AND_ASSIGN(VpnServer);
};

}  // namespace vpn

}  // namespace lego
