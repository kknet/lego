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
    lego::common::SignalRegister();
    auto int_res = lego::client::VpnClient::Instance()->Init(
            "0.0.0.0",
            7981,
            "id:139.59.91.63:9001,id:139.59.47.229:9001,id:46.101.152.5:9001,id:165.227.18.179:9001,id:165.227.60.177:9001,id:206.189.239.148:9001,id:121.201.1.186:9001,id:121.201.10.101:9001,id:121.201.102.126:9001",
            "./conf/",
            "3.0.0",
            "");
    if (int_res == "ERROR") {
        std::cout << "init client failed: " << int_res << std::endl;
        return 1;
    }

    lego::init::Command cmd;
    if (!cmd.Init(false, true, false)) {
        std::cout << "init cmd failed!" << std::endl;
        return 1;
    }
    cmd.Run();
    return 0;
}