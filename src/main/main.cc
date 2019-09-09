#include <iostream>
#include <queue>
#include <vector>

#include "common/log.h"
#include "init/network_init.h"

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    lego::init::NetworkInit net_init;
    lego::common::SignalRegister();
    net_init.Init(argc, argv);
    return 0;
}
