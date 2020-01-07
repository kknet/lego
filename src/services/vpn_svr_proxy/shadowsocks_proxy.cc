#include "stdafx.h"
#include "services/vpn_svr_proxy/shadowsocks_proxy.h"

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "common/global_info.h"
#include "common/random.h"
#include "common/string_utils.h"
#include "common/encode.h"
#include "common/user_property_key_define.h"
#include "ip/ip_with_country.h"
#include "security/ecdh_create_key.h"
#include "network/route.h"
#include "client/trans_client.h"
#include "sync/key_value_sync.h"
#include "services/vpn_server/vpn_server.h"
#include "services/vpn_svr_proxy/proxy_utils.h"
#include "services/vpn_route/route_tcp.h"
#include "services/vpn_server/vpn_route.h"

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
        return kProxyError;
    }

    if (ip::IpWithCountry::Instance()->Init(
            "./conf/geolite.conf",
            "./conf/geo_country.conf") != ip::kIpSuccess) {
        PROXY_ERROR("init ip config with args failed!");
        return kProxyError;
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

    network::DhtManager::Instance();
    network::UniversalManager::Instance();
    network::Route::Instance();
    if (InitTransport() != kProxySuccess) {
        PROXY_ERROR("init transport failed!");
        return kProxyError;
    }

    if (InitHttpTransport() != transport::kTransportSuccess) {
        PROXY_ERROR("init http transport failed!");
        return kProxyError;
    }

    if (InitNetworkSingleton() != kProxySuccess) {
        PROXY_ERROR("InitNetworkSingleton failed!");
        return kProxyError;
    }

    conf_.Get("lego", "vpn_route_port", vpn_route_port_);
    uint32_t vpn_vip_level = 0;
    conf_.Get("lego", "vpn_vip_level", vpn_vip_level);
    if (InitTcpRelay(vpn_vip_level) != kProxySuccess) {
        PROXY_ERROR("init tcp relay failed!");
        return kProxyError;
    }

    conf_.Get("lego", "vpn_server_port", vpn_server_port_);
    if (StartShadowsocks() != kProxySuccess) {
        PROXY_ERROR("start shadowsocks failed!");
        return kProxyError;
    }

    for (int i = 0; i < 7; ++i) {
        if (init::UpdateVpnInit::Instance()->InitSuccess()) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::microseconds(1000 * 1000));
    }

    if (!init::UpdateVpnInit::Instance()->InitSuccess()) {
        PROXY_ERROR("init::UpdateVpnInit::Instance()->InitSuccess failed!");
        return kProxyError;
    }

    if (InitCommand() != kProxySuccess) {
        PROXY_ERROR("InitNetworkSingleton failed!");
        return kProxyError;
    }

    std::string gid;
    std::map<std::string, std::string> attrs;
    lego::client::TransactionClient::Instance()->Transaction(
            "",
            0,
            "",
            attrs,
            common::kConsensusCreateAcount,
            gid);
    // check account address valid
    inited_ = true;
    cmd_.Run();
    transport_->Stop();
    vpn::VpnServer::Instance()->Stop();
    network::DhtManager::Instance()->Destroy();
    std::cout << "exit now." << std::endl;
    exit(0);
    return kProxySuccess;
}

int ShadowsocksProxy::InitTcpRelay(uint32_t vip_level) {
    if (vpn_route_port_ == 0) {
        return kProxySuccess;
    }

    uint32_t route_network_id = network::kVpnRouteNetworkId;
    switch (vip_level) {
        case 1:
            route_network_id = network::kVpnRouteVipLevel1NetworkId;
            break;
        case 2:
            route_network_id = network::kVpnRouteVipLevel2NetworkId;
            break;
        case 3:
            route_network_id = network::kVpnRouteVipLevel3NetworkId;
            break;
        case 4:
            route_network_id = network::kVpnRouteVipLevel4NetworkId;
            break;
        case 5:
            route_network_id = network::kVpnRouteVipLevel5NetworkId;
            break;
        default:
            break;
    }

    vpn_route_ = std::make_shared<VpnProxyNode>(route_network_id);
    int res = vpn_route_->Init();
    if (res != dht::kDhtSuccess) {
        vpn_route_ = nullptr;
        PROXY_ERROR("node join network [%u] [%d] failed!", route_network_id, res);
        return kProxyError;
    }

    res = vpn::VpnRoute::Instance()->Init(vip_level);
    if (res != vpnroute::kVpnRouteSuccess) {
        return kProxyError;
    }

    return kProxySuccess;
}

void ShadowsocksProxy::GetShadowsocks(uint16_t& route_port, uint16_t& vpn_port) {
    route_port = vpn_route_port_;
    auto last_ptr = vpn::VpnServer::Instance()->last_listen_ptr();
    if (last_ptr != nullptr) {
        vpn_port = last_ptr->vpn_port;
    }
}

int ShadowsocksProxy::StartShadowsocks() {
    if (vpn_server_port_ == 0) {
        return kProxySuccess;
    }

    vpn_proxy_ = std::make_shared<VpnProxyNode>(network::kVpnNetworkId);
    if (vpn_proxy_->Init() != network::kNetworkSuccess) {
        vpn_proxy_ = nullptr;
        PROXY_ERROR("node join network [%u] failed!", network::kVpnNetworkId);
        return kProxyError;
    }

    if (VpnServer::Instance()->Init() != kVpnsvrSuccess) {
        return kProxyError;
    }

    return kProxySuccess;
}

}  // namespace vpn

}  // namespace lego
