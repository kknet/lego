#pragma once

#include "common/tick.h"
#include "init/network_init.h"
#include "network/shard_network.h"
#include "services/vpn_svr_proxy/proxy_dht.h"

namespace lego {

namespace vpn {

struct ShadowsocksConf {
    std::string mode;
    std::string passwd;
    std::string method;
    uint16_t port;
    uint32_t timeout;
    uint32_t pid;
};
typedef std::shared_ptr<ShadowsocksConf> ShadowsocksConfPtr;

typedef network::ShardNetwork<ProxyDht> VpnProxyNode;
typedef std::shared_ptr<VpnProxyNode> VpnProxyNodePtr;

class ShadowsocksProxy : public init::NetworkInit {
public:
    static ShadowsocksProxy* Instance();
    virtual int Init(int argc, char** argv);
    ShadowsocksConfPtr GetShadowsocks();

private:
    ShadowsocksProxy();
    ~ShadowsocksProxy();

    int StartShadowsocks();
    int KillShadowsocks(const ShadowsocksConfPtr& socks_ptr);
    int RunCommand(const std::string& cmd, const std::string& succ_res);
    void CheckVpnStatus();
    void ShiftVpnPeriod();
    int CreateVpnProxyNetwork();
    bool CheckVpnExists(const std::string& passwd);

    static const uint32_t kMaxShadowsocksCount = 3u;
    static const int64_t kShowdowsocksShiftPeriod = 3600ll * 1000ll * 1000ll;
    static const uint32_t kCheckVpnServerStatusPeriod = 3u;

    ShadowsocksConfPtr socks_[kMaxShadowsocksCount];
    int32_t now_valid_begin_{ -1 };
    common::Tick tick_;
    common::Tick tick_status_;
    std::mutex socks_mutex_;
    VpnProxyNodePtr vpn_proxy_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(ShadowsocksProxy);
};

}  // namespace vpn

}  // namespace lego
