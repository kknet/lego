#include <stdlib.h>
#include <math.h>

#include <iostream>

#include <gtest/gtest.h>

#include "common/utils.h"

#define private public
#include "common/global_info.h"
#include "services/vpn_svr_proxy/shadowsocks_proxy.h"
#include "services/vpn_svr_proxy/proxy_utils.h"

namespace lego {

namespace vpn {

namespace test {

class TestVpnSvrProxy : public testing::Test {
public:
    static void SetUpTestCase() {      
        log4cpp::PropertyConfigurator::configure("./conf/log4cpp.properties");
    }

    static void TearDownTestCase() {
    }

    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(TestVpnSvrProxy, All) {
    ShadowsocksProxy socks_proxy;
    std::cout << "now start" << std::endl;
    common::GlobalInfo::Instance()->config_local_ip_ = "127.0.0.1";
    std::string cmd("ps -ef | grep gpgk | awk -F' ' '{print $2}' | xargs kill -9");
    ASSERT_TRUE(socks_proxy.RunCommand(cmd, "") == kProxySuccess);

    for (uint32_t i = 0; i < 10; ++i) {
        ASSERT_TRUE(socks_proxy.StartShadowsocks() == kProxySuccess);
    }
    std::cout << "start success." << std::endl;
}

}  // namespace test

}  // namespace common

}  // namespace lego
