#include <iostream>

#include "common/log.h"
#include "init/command.h"
#include "client/vpn_client.h"
#include "client/client_utils.h"

int main(int argc, char** argv) {
    if (lego::client::VpnClient::Instance()->Init(
            "./conf/lego.conf") != "OK") {
        std::cout << "init client failed!" << std::endl;
        return 1;
    }

    std::vector<lego::client::VpnServerNodePtr> nodes;
    lego::client::VpnClient::Instance()->GetVpnServerNodes("US", 2, nodes);
    std::cout << "get vpn_nodes size: " << nodes.size() << std::endl;
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        std::cout << "get vpn_info: " << nodes[i]->ip << ":" << nodes[i]->port
            << ", " << nodes[i]->encrypt_type << ", " << nodes[i]->passwd << std::endl;
    }
    lego::init::Command cmd;
    if (!cmd.Init(false, true)) {
        std::cout << "init cmd failed!" << std::endl;
        return 1;
    }
    cmd.Run();
    return 0;
}