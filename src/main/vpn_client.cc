#include <iostream>

#include "common/log.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "init/command.h"
#include "client/vpn_client.h"
#include "client/client_utils.h"

int main(int argc, char** argv) {
    if (lego::client::VpnClient::Instance()->Init(
            "./conf/lego.conf") != "OK") {
        std::cout << "init client failed!" << std::endl;
        return 1;
    }
    std::string create_acc_gid;
    lego::client::VpnClient::Instance()->Transaction("", 0, create_acc_gid);
    std::cout << "create acc gid: " << lego::common::Encode::HexEncode(create_acc_gid);
    while (lego::client::VpnClient::Instance()->GetTransactionInfo(create_acc_gid).empty()) {
        std::this_thread::sleep_for(std::chrono::microseconds(50000ull));
    }
    std::cout << "success create account: " << lego::common::Encode::HexEncode(
            lego::common::GlobalInfo::Instance()->id()) << std::endl;
    return 0;
    std::string tx_gid;
    lego::client::VpnClient::Instance()->Transaction("to", 10, tx_gid);
    auto res = lego::client::VpnClient::Instance()->GetTransactionInfo(tx_gid);
    while (res.empty()) {
        std::this_thread::sleep_for(std::chrono::microseconds(50000ull));
        res = lego::client::VpnClient::Instance()->GetTransactionInfo(tx_gid);
    }
    std::cout << "transaction success: " << res << std::endl;
    return 0;

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