#pragma once

#include "common/tick.h"
#include "init/network_init.h"
#include "network/shard_network.h"
#include "services/vpn_svr_proxy/proxy_dht.h"

namespace lego {

namespace vpn {

typedef network::ShardNetwork<ProxyDht> VpnProxyNode;
typedef std::shared_ptr<VpnProxyNode> VpnProxyNodePtr;

class ShadowsocksProxy : public init::NetworkInit {
public:
    static ShadowsocksProxy* Instance();
    virtual int Init(int argc, char** argv);
    void GetShadowsocks(uint16_t& route_port, uint16_t& vpn_port);

private:
    ShadowsocksProxy();
    ~ShadowsocksProxy();

    void HandleMessage(transport::protobuf::Header& header);
    int StartShadowsocks();
    int InitTcpRelay(uint32_t vip_level);

    static const uint32_t kMaxShadowsocksCount = 3u;
    static const int64_t kShowdowsocksShiftPeriod = 3600ll * 1000ll * 1000ll;
    static const uint32_t kCheckVpnServerStatusPeriod = 3u;

    common::Tick tick_;
    common::Tick tick_status_;
    VpnProxyNodePtr vpn_proxy_{ nullptr };
    VpnProxyNodePtr vpn_route_{ nullptr };
    std::string vpn_bin_path_;
    uint16_t vpn_server_port_{ 0 };
    uint16_t vpn_route_port_{ 0 };

    DISALLOW_COPY_AND_ASSIGN(ShadowsocksProxy);
};

}  // namespace vpn

}  // namespace lego
