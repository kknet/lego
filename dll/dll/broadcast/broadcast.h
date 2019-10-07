#pragma once

#include <memory>
#include <unordered_map>

#include "common/utils.h"
#include "transport//proto/transport.pb.h"
#include "broadcast/broadcast_utils.h"

namespace lego {

namespace dht {
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
    class Node;
    typedef std::shared_ptr<Node> NodePtr;
}  // namespace dht

namespace broadcast {

class Broadcast {
public:
    virtual void Broadcasting(
            dht::BaseDhtPtr& dht_ptr,
            transport::protobuf::Header& message) = 0;

protected:
    Broadcast();
    virtual ~Broadcast();
    bool TestForEvilNode(float evil_rate);
    void Send(
            dht::BaseDhtPtr& dht_ptr,
            transport::protobuf::Header& message,
            const std::vector<dht::NodePtr>& nodes);
    inline uint32_t GetNeighborCount(transport::protobuf::Header& message) {
        if (message.broadcast().has_neighbor_count()) {
            return message.broadcast().neighbor_count();
        }

        return kBroadcastDefaultNeighborCount;
    }

private:
    static const uint32_t kMaxMessageHashCount = 10u * 1024u * 1024u;

    DISALLOW_COPY_AND_ASSIGN(Broadcast);
};

}  // namespace broadcast

}  // namespace lego
