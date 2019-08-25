#include <iostream>
#include <thread>

#include "common/log.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/config.h"
#include "init/command.h"
#include "client/vpn_client.h"
#include "client/client_utils.h"

int main(int argc, char** argv) {
    lego::common::Config conf;
    if (!conf.Init("./conf/lego.conf")) {
        return 1;
    }
    std::string local_ip;
    conf.Get("lego", "local_ip", local_ip);
    uint16_t local_port;
    conf.Get("lego", "local_port", local_port);
    std::string bootstrap;
    conf.Get("lego", "bootstrap", bootstrap);
    bool show_cmd;
    conf.Get("lego", "show_cmd", show_cmd);
    bool run_tx = false;
    conf.Get("lego", "run_tx", run_tx);

    auto int_res = lego::client::VpnClient::Instance()->Init(
            local_ip,
            local_port,
            bootstrap,
            "./conf/lego.conf",
            "./log/lego.log",
            "./conf/log4cpp.properties");
    if (int_res == "ERROR") {
        std::cout << "init client failed: " << int_res << std::endl;
        return 1;
    }

//     if (!lego::client::VpnClient::Instance()->ConfigExists()) {
//         std::string create_acc_gid;
//         lego::client::VpnClient::Instance()->Transaction("", 0, create_acc_gid);
//         std::cout << "create acc gid: " <<
//                 lego::common::Encode::HexEncode(create_acc_gid) << std::endl;
//         while (lego::client::VpnClient::Instance()->GetTransactionInfo(create_acc_gid).empty()) {
//             std::this_thread::sleep_for(std::chrono::microseconds(50000ull));
//         }
//         std::cout << "success create account: " << lego::common::Encode::HexEncode(
//                 lego::common::GlobalInfo::Instance()->id()) << std::endl;
//     }
//     std::string tx_gid;
//     lego::client::VpnClient::Instance()->Transaction(
//             lego::common::Encode::HexDecode(
//             "324ec69ab59c57eb582cdd243058e8255e2bc309ac06df3917b4af404353b44b"),
//             10,
//             tx_gid);
//     auto res = lego::client::VpnClient::Instance()->GetTransactionInfo(tx_gid);
//     while (res.empty()) {
//         std::this_thread::sleep_for(std::chrono::microseconds(50000ull));
//         res = lego::client::VpnClient::Instance()->GetTransactionInfo(tx_gid);
//     }
//     std::cout << "transaction success: " << res << std::endl;
//     return 0;
// 
//     std::vector<lego::client::VpnServerNodePtr> nodes;
//     lego::client::VpnClient::Instance()->GetVpnServerNodes("US", 2, nodes);
//     std::cout << "get vpn_nodes size: " << nodes.size() << std::endl;
//     for (uint32_t i = 0; i < nodes.size(); ++i) {
//         std::cout << "get vpn_info: " << nodes[i]->ip << ":" << nodes[i]->port
//             << ", " << nodes[i]->encrypt_type << ", " << nodes[i]->passwd << std::endl;
//     }
    lego::init::Command cmd;
    if (!cmd.Init(false, show_cmd, run_tx)) {
        std::cout << "init cmd failed!" << std::endl;
        return 1;
    }
    cmd.Run();
    return 0;
}