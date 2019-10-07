#pragma once

#include <memory>
#include <unordered_map>

#include "common/utils.h"
#include "common/tick.h"
#include "network/network_utils.h"

namespace lego {

namespace dht {
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
}  // namespace dht

namespace network {

class DhtManager {
public:
    static DhtManager* Instance();
    void RegisterDht(uint32_t net_id, dht::BaseDhtPtr& dht);
    void UnRegisterDht(uint32_t net_id);
    dht::BaseDhtPtr GetDht(uint32_t net_id);
    void Init();
    void Destroy();

private:
    DhtManager();
    ~DhtManager();
    void NetworkDetection();

    static const uint32_t kNetworkDetectPeriod = 3 * 1000 * 1000;
    static const uint32_t kNetworkDetectionLimitNum = 16;

    dht::BaseDhtPtr* dhts_{ nullptr };
    common::Tick tick_;
    std::unordered_map<uint32_t, dht::BaseDhtPtr> dht_map_;
    std::mutex dht_map_mutex_;

    DISALLOW_COPY_AND_ASSIGN(DhtManager);
};

}  // namespace network

}  // namespace lego
