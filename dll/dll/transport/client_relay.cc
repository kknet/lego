#include "stdafx.h"
#include "transport/client_relay.h"

#include <functional>

namespace lego {

namespace transport {

ClientRelay::ClientRelay() {
    tick_.CutOff(
            kCheckClientTimeoutPeriod,
            std::bind(&ClientRelay::CheckTimeoutClient, this));
}

ClientRelay::~ClientRelay() {}

ClientRelay* ClientRelay::Instance() {
    static ClientRelay ins;
    return &ins;
}

void ClientRelay::AddClient(
        const std::string& id,
        const std::string& ip,
        uint16_t port) {
    auto client_node = std::make_shared<ClientNode>(ip, port);
    std::lock_guard<std::mutex> guard(client_node_map_mutex_);
    client_node_map_[id] = client_node;  // just cover
}

ClientNodePtr ClientRelay::GetClient(const std::string& id) {
    std::lock_guard<std::mutex> guard(client_node_map_mutex_);
    auto iter = client_node_map_.find(id);
    if (iter != client_node_map_.end()) {
        auto item_ptr = iter->second;
        client_node_map_.erase(iter);
        return item_ptr;
    }
    return nullptr;
}

void ClientRelay::CheckTimeoutClient() {
    {
        auto now_tm = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> guard(client_node_map_mutex_);
        for (auto iter = client_node_map_.begin(); iter != client_node_map_.end();) {
            if (iter->second->timeout <= now_tm) {
                client_node_map_.erase(iter++);
            } else {
                ++iter;
            }
        }
    }
    tick_.CutOff(
            kCheckClientTimeoutPeriod,
            std::bind(&ClientRelay::CheckTimeoutClient, this));
}

}  // namespace transport

}  // namespace transport