#include "services/vpn_svr_proxy/shadowsocks_proxy.h"

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "common/global_info.h"
#include "common/random.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "ip/ip_with_country.h"
#include "security/ecdh_create_key.h"
#include "network/route.h"
#include "client/trans_client.h"
#include "services/vpn_server/vpn_server.h"
#include "services/vpn_svr_proxy/proxy_utils.h"
#include "services/vpn_route/route_tcp.h"

namespace lego {

namespace vpn {

ShadowsocksProxy::ShadowsocksProxy() {
    network::Route::Instance()->RegisterMessage(
            common::kServiceMessage,
            std::bind(&ShadowsocksProxy::HandleMessage, this, std::placeholders::_1));
//     tick_status_.CutOff(
//             kCheckVpnServerStatusPeriod,
//             std::bind(&ShadowsocksProxy::CheckVpnStatus, this));
}

ShadowsocksProxy::~ShadowsocksProxy() {}

void ShadowsocksProxy::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() != common::kServiceMessage) {
        return;
    }

    auto dht = network::Route::Instance()->GetDht(header.des_dht_key(), header.universal());
    assert(dht);
    dht->HandleMessage(header);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("socks proxy", header);
}

ShadowsocksProxy* ShadowsocksProxy::Instance() {
    static ShadowsocksProxy ins;
    return &ins;
}

int ShadowsocksProxy::Init(int argc, char** argv) {
    std::lock_guard<std::mutex> guard(init_mutex_);
    if (inited_) {
        PROXY_ERROR("network inited!");
        return kProxyError;
    }

    if (InitConfigWithArgs(argc, argv) != kProxySuccess) {
        PROXY_ERROR("init config with args failed!");
        return kProxySuccess;
    }

    if (ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf") != ip::kIpSuccess) {
        PROXY_ERROR("init ip config with args failed!");
        return kProxySuccess;
    }

    if (common::GlobalInfo::Instance()->Init(conf_) != common::kCommonSuccess) {
        PROXY_ERROR("init global info failed!");
        return kProxyError;
    }

    if (SetPriAndPubKey("") != kProxySuccess) {
        PROXY_ERROR("set node private and public key failed!");
        return kProxyError;
    }

    if (security::EcdhCreateKey::Instance()->Init() != security::kSecuritySuccess) {
        PROXY_ERROR("init ecdh create secret key failed!");
        return kProxyError;
    }

//     if (InitTcpRelay() != kProxySuccess) {
//         PROXY_ERROR("init tcp relay failed!");
//         return kProxyError;
//     }

    if (InitTransport() != kProxySuccess) {
        PROXY_ERROR("init transport failed!");
        return kProxyError;
    }

    if (InitNetworkSingleton() != kProxySuccess) {
        PROXY_ERROR("InitNetworkSingleton failed!");
        return kProxyError;
    }

    if (InitTcpRelay() != kProxySuccess) {
        PROXY_ERROR("init tcp relay failed!");
        return kProxyError;
    }

    if (StartShadowsocks() != kProxySuccess) {
        PROXY_ERROR("start shadowsocks failed!");
        return kProxyError;
    }

    if (CreateVpnProxyNetwork() != kProxySuccess) {
        PROXY_ERROR("create vpn proxy network failed!");
        return kProxyError;
    }

    if (InitCommand() != kProxySuccess) {
        PROXY_ERROR("InitNetworkSingleton failed!");
        return kProxyError;
    }

    std::string gid;
    client::TransactionClient::Instance()->Transaction("", 0, gid);
    inited_ = true;
    cmd_.Run();
    return kProxySuccess;
}

int ShadowsocksProxy::InitTcpRelay() {
    int res = vpnroute::TcpRoute::Instance()->Init(
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port() + 32);
    if (res != vpnroute::kVpnRouteSuccess) {
        return kProxyError;
    }

    return kProxySuccess;
}

ShadowsocksConfPtr ShadowsocksProxy::GetShadowsocks() {
    return nullptr;
}

int ShadowsocksProxy::StartShadowsocks() {
    if (VpnServer::Init(
            common::GlobalInfo::Instance()->config_local_ip(),
            common::GlobalInfo::Instance()->config_local_port() + 31,
            "password",
            "",
            "aes-128-cfb") != kVpnsvrSuccess) {
        return kProxyError;
    }
    return kProxySuccess;
}

int ShadowsocksProxy::CreateVpnProxyNetwork() {
    vpn_proxy_ = std::make_shared<VpnProxyNode>(network::kVpnNetworkId);
    if (vpn_proxy_->Init() != network::kNetworkSuccess) {
        vpn_proxy_ = nullptr;
        PROXY_ERROR("node join network [%u] failed!", network::kVpnNetworkId);
        return kProxyError;
    }

    return kProxySuccess;
}

}  // namespace vpn

}  // namespace lego
