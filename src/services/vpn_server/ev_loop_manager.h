#pragma once

#include "services/vpn_server/vpn_svr_utils.h"
#include "services/vpn_server/server.h"

namespace lego {

namespace vpn {

class EvLoopManager {
public:
    static EvLoopManager* Instance();

    struct ev_loop* loop() {
        return loop_;
    }

private:
    EvLoopManager();
    ~EvLoopManager();
    void InitLoop();

    struct ev_loop* loop_{ nullptr };
    std::shared_ptr<std::thread> loop_thread_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(EvLoopManager);
};

}  // namespace vpn

}  // namespace lego
