#include <iostream>

#include "common/log.h"
#include "init/command.h"
#include "client/vpn_client.h"
#include "client/client_utils.h"

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    lego::client::VpnClient client;
    if (client.Init("./conf/lego.conf") != lego::client::kClientSuccess) {
        std::cout << "init client failed!" << std::endl;
        return 1;
    }

    lego::init::Command cmd;
    if (!cmd.Init(false, true)) {
        std::cout << "init cmd failed!" << std::endl;
        return 1;
    }

    return 0;
}