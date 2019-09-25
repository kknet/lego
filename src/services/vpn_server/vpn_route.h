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

class VpnRoute {
public:
    static VpnRoute* Instance();
    int Init();
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

private:
    VpnRoute();
    ~VpnRoute();
    void RotationServer();
    void StartMoreServer();

    static const uint32_t kStakingCheckingPeriod = 10 * 1000 * 1000;
    static const uint32_t kAccountCheckPeriod = 10 * 1000 * 1000;

    std::deque<std::shared_ptr<listen_ctx_t>> listen_ctx_queue_;
    common::Tick new_vpn_server_tick_;
    std::shared_ptr<listen_ctx_t> default_ctx_{ nullptr };
    std::shared_ptr<listen_ctx_t> last_listen_ptr_{ nullptr };
    std::set<uint16_t> started_port_set_;

    DISALLOW_COPY_AND_ASSIGN(VpnRoute);
};

}  // namespace vpn

}  // namespace lego
