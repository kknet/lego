#include <iostream>

#include "common/log.h"
#include "services/vpn_svr_proxy/shadowsocks_proxy.h"

int main(int argc, char** argv) {
    log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    lego::vpn::ShadowsocksProxy::Instance()->Init(argc, argv);
    return 0;
}