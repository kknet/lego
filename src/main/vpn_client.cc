#include <iostream>
#include <thread>

#include "common/log.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "common/config.h"
#include "common/random.h"
#include "init/command.h"
#include "client/vpn_client.h"
#include "client/client_utils.h"

int main(int argc, char** argv) {
    lego::common::Config conf;
    std::cout << "init config now." << std::endl;
    if (!conf.Init("./conf/lego.conf")) {
        return 1;
    }
    std::cout << "init config success." << std::endl;
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
    lego::common::SignalRegister();
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
    lego::init::Command cmd;
    if (!cmd.Init(false, show_cmd, run_tx)) {
        std::cout << "init cmd failed!" << std::endl;
        return 1;
    }
    cmd.Run();
    return 0;
}