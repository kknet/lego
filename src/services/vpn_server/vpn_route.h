#pragma once

#include <thread>
#include <memory>
#include <unordered_map>
#include <queue>

#include "common/tick.h"
#include "common/thread_safe_queue.h"
#include "block/proto/block.pb.h"
#include "transport/proto/transport.pb.h"
#include "services/vpn_server/vpn_svr_utils.h"
#include "services/vpn_server/server.h"

namespace lego {

namespace vpn {

struct LoginCountryItem {
    uint32_t country;
    uint32_t count;
};
typedef std::shared_ptr<LoginCountryItem> LoginCountryItemPtr;

class VpnRoute {
public:
    static VpnRoute* Instance();
    int Init(uint32_t vip_level);
    void Stop();

    std::shared_ptr<listen_ctx_t> last_listen_ptr() {
        if (last_listen_ptr_ == nullptr) {
            return default_ctx_;
        }
        return last_listen_ptr_;
    }

    std::shared_ptr<listen_ctx_t> default_ctx() {
        return default_ctx_;
    }

    common::ThreadSafeQueue<LoginCountryItemPtr>& login_country_queue() {
        return login_country_queue_;
    }

    common::ThreadSafeQueue<BandwidthInfoPtr>& route_bandwidth_queue() {
        return route_bandwidth_queue_;
    }

    void HandleVpnResponse(
            transport::protobuf::Header& header,
            block::protobuf::BlockMessage& block_msg);

    std::unordered_map<std::string, BandwidthInfoPtr>& account_bindwidth_map() {
        return account_bindwidth_map_;
    }

private:
    VpnRoute();
    ~VpnRoute();
    void RotationServer();
    void StartMoreServer();
    void CheckLoginClient();
    void SendNewClientLogin(const std::string& val);
    void CheckRouteQueue();
    void CheckServerQueue();

    static const uint32_t kStakingCheckingPeriod = 10 * 1000 * 1000;
    static const uint32_t kAccountCheckPeriod = 10 * 1000 * 1000;
    static const uint32_t kCheckLoginCLientPeriod = 10 * 1000 * 1000;
    static const int64_t kCheckServerQueuePeriod = 3ll * 1000ll * 1000ll;
    static const int64_t kCheckRouteQueuePeriod = 3ll * 1000ll * 1000ll;

    std::deque<std::shared_ptr<listen_ctx_t>> listen_ctx_queue_;
    common::Tick new_vpn_server_tick_;
    std::shared_ptr<listen_ctx_t> default_ctx_{ nullptr };
    std::shared_ptr<listen_ctx_t> last_listen_ptr_{ nullptr };
    std::set<uint16_t> started_port_set_;
    common::ThreadSafeQueue<LoginCountryItemPtr> login_country_queue_;
    common::ThreadSafeQueue<BandwidthInfoPtr> route_bandwidth_queue_;
    common::Tick check_login_client_;
    common::Tick check_route_queue_;
    uint32_t now_day_timestamp_{ 0 };
    std::unordered_map<uint32_t, LoginCountryItemPtr> client_map_;
    uint32_t check_login_tiems_{ 0 };
    std::unordered_map<std::string, BandwidthInfoPtr> vip_check_account_map_;
    std::mutex vip_check_account_map_mutex_;
    uint32_t this_node_vip_level_{ common::kNotVip };
    uint32_t this_node_route_network_id_{ network::kVpnRouteNetworkId };

    // just vpn server, thread safe
    std::unordered_map<std::string, BandwidthInfoPtr> account_bindwidth_map_;

    DISALLOW_COPY_AND_ASSIGN(VpnRoute);
};

}  // namespace vpn

}  // namespace lego
