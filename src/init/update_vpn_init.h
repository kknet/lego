#pragma once

#include <deque>

#include "common/tick.h"
#include "transport/proto/transport.pb.h"
#include "client/proto/client.pb.h"
#include "dht/proto/dht.pb.h"
#include "init/init_utils.h"

namespace lego {

namespace init {

struct VpnServerNode {
    VpnServerNode(
            const std::string& in_ip,
            uint16_t s_port,
            uint16_t r_port,
            const std::string& skey,
            const std::string& dkey,
            const std::string& pkey,
            const std::string& id,
            bool new_node)
            : ip(in_ip),
            svr_port(s_port),
            route_port(r_port),
            seckey(skey),
            dht_key(dkey),
            pubkey(pkey),
            acccount_id(id),
            new_get(new_node) {
        timeout = std::chrono::steady_clock::now() + std::chrono::seconds(3600);
    }
    std::string ip;
    uint16_t svr_port;
    uint16_t route_port;
    std::string seckey;
    std::string dht_key;
    std::string pubkey;
    std::string acccount_id;
    bool new_get{ false };
    std::chrono::steady_clock::time_point timeout;
};
typedef std::shared_ptr<VpnServerNode> VpnServerNodePtr;

class UpdateVpnInit {
public:
    static UpdateVpnInit* Instance();
    void GetInitMessage(dht::protobuf::InitMessage& init_msg);
    void SetVersionInfo(const std::string& ver);
    uint64_t max_free_bandwidth() {
        return max_free_bandwidth_;
    }

    uint64_t max_vip_bandwidth() {
        return max_vip_bandwidth_;
    }

    bool InitSuccess();
    void BootstrapInit(
            const std::string& ver,
            const dht::protobuf::BootstrapResponse& boot_res);

private:
    UpdateVpnInit();
    ~UpdateVpnInit();
    void GetVpnNodes();
    void GetNetworkNodes(
            const std::vector<std::string>& country_vec,
            uint32_t network_id);
    void HandleNodes(bool is_route, const dht::protobuf::VpnNodeInfo& vpn_node);

    static const uint32_t kGetVpnNodesPeriod = 10 * 1000 * 1000;
    static const uint32_t kMaxGetVpnNodesNum = 4u;

    common::Tick check_ver_tick_;
    common::Tick update_vpn_nodes_tick_;
    std::string ver_buf_[2];
    uint32_t valid_idx_{ 0 };
    std::map<std::string, std::deque<VpnServerNodePtr>> vpn_nodes_map_;
    std::mutex vpn_nodes_map_mutex_;
    std::map<std::string, std::deque<VpnServerNodePtr>> route_nodes_map_;
    std::mutex route_nodes_map_mutex_;
    std::vector<std::string> country_vec_;
    std::mutex country_vec_mutex_;
    volatile uint64_t max_free_bandwidth_{ 2048llu * 1024llu * 1024llu };
    volatile uint64_t max_vip_bandwidth_{ 10llu * 1024llu * 1024llu * 1024llu };

};

}  // namespace init

}  // namespace lego
