#pragma once

#include <memory>
#include <unordered_map>
#include <mutex>

#include "common/utils.h"
#include "common/tick.h"
#include "nat_traverse/proto/nat_proto.h"

namespace lego {

namespace dht {
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
    class Node;
    typedef std::shared_ptr<Node> NodePtr;
}  // namespace dht

namespace transport {
    class Transport;
    typedef std::shared_ptr<Transport> TransportPtr;
}  // namespace transport

namespace nat {

struct DetectionItem {
    DetectionItem(dht::NodePtr& in_node) : node(in_node), detected_times(0) {}
    dht::NodePtr node;
    uint32_t detected_times;
};

typedef std::shared_ptr<DetectionItem> DetectionItemPtr;

class Detection {
public:
    Detection(dht::BaseDhtPtr base_dht);
    ~Detection();
    void Destroy();
    void AddTarget(dht::NodePtr& node);
    void Remove(uint64_t dht_key_hash);
    void RegisterNatMessage();
    void HandleMessage(transport::protobuf::Header& msg);

private:
    void Run();
    // set ttl to try nat
    void SendTtlPacket(DetectionItemPtr& item);
    void HandleDetectionRequest(
            transport::protobuf::Header& header,
            protobuf::NatMessage& nat_msg);

    static const uint32_t kDetecionMaxTimes = 10u;
    static const uint32_t kDetectionPeriod = 600 * 1000;
    static const uint32_t kDetecitonTtl = 4u;

    std::unordered_map<uint64_t, DetectionItemPtr> node_map_;
    std::mutex node_map_mutex_;
    dht::BaseDhtPtr base_dht_{ nullptr };
    common::Tick tick_;
    bool destroy_{ false };

    DISALLOW_COPY_AND_ASSIGN(Detection);
};

}  // namespace nat

}  // namespace lego
