#pragma once

#include <chrono>
#include <mutex>
#include <unordered_map>

#include "dht/base_dht.h"
#include "dht/node.h"
#include "services/proto/service.pb.h"

namespace lego {

namespace vpn {

struct AccountVpnUseInfo {
    AccountVpnUseInfo(const std::string& pk, const std::string& ch, const std::string& re)
            : pubkey(pk), sign_cha(ch), sign_res(re) {
        prev_time = std::chrono::steady_clock::now();
        pre_duration = std::chrono::milliseconds(0);
    }
    std::chrono::steady_clock::time_point prev_time;
    std::chrono::milliseconds pre_duration;
    std::string pubkey;
    std::string sign_cha;
    std::string sign_res;
};
typedef std::shared_ptr<AccountVpnUseInfo> AccountVpnUseInfoPtr;

class ProxyDht : public dht::BaseDht {
public:
    ProxyDht(transport::TransportPtr& transport, dht::NodePtr& local_node);
    virtual ~ProxyDht();
    virtual void HandleMessage(transport::protobuf::Header& msg);

private:
    void HandleGetSocksRequest(
            transport::protobuf::Header& msg,
            service::protobuf::ServiceMessage& svr_msg);
    int CheckSign(const service::protobuf::GetVpnInfoRequest& vpn_req);
    int ResetUserUseTimer(const service::protobuf::GetVpnInfoRequest& vpn_req);

    static const int64_t kStakingPeriod = 600ull * 1000ull;

    std::unordered_map<std::string, AccountVpnUseInfoPtr> account_vpn_use_map_;
    std::mutex account_vpn_use_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(ProxyDht);
};

}  // namespace vpn

}  // namespace lego
