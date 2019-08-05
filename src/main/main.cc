#include <iostream>

#include "common/log.h"
#include "init/network_init.h"

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    lego::init::NetworkInit net_init;
    net_init.Init(argc, argv);
    return 0;
}
