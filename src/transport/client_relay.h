#pragma once

#include <unordered_map>

#include "common/tick.h"
#include "transport/transport_utils.h"

namespace lego {

namespace transport {


struct ClientNode {
    ClientNode(const std::string& in_ip, uint16_t in_port) : ip(in_ip), port(in_port) {
        static const uint32_t kClientTimeout = 30u * 1000u * 1000u;
        timeout = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kClientTimeout));
    }
    std::string ip;
    uint16_t port;
    std::chrono::steady_clock::time_point timeout;
};

typedef std::shared_ptr<ClientNode> ClientNodePtr;

class ClientRelay {
public:
    static ClientRelay* Instance();
    void AddClient(const std::string& id, const std::string& ip, uint16_t port);
    ClientNodePtr GetClient(const std::string& id);

private:
    ClientRelay();
    ~ClientRelay();
    void CheckTimeoutClient();

    static const uint32_t kCheckClientTimeoutPeriod = 3u * 1000u * 1000u;

    std::unordered_map<std::string, ClientNodePtr> client_node_map_;
    std::mutex client_node_map_mutex_;
    common::Tick tick_;

    DISALLOW_COPY_AND_ASSIGN(ClientRelay);
};

}  // namespace transport

}  // namespace transport
