#pragma once

#include "common/utils.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"

namespace lego {

namespace dht {
    class BaseDht;
    typedef std::shared_ptr<BaseDht> BaseDhtPtr;
}  // namespace dht

namespace broadcast {
    class Broadcast;
    typedef std::shared_ptr<Broadcast> BroadcastPtr;
}  // namespace broadcast

namespace network {

class Route {
public:
    static Route* Instance();
    int Send(transport::protobuf::Header& message);
    int SendToLocal(transport::protobuf::Header& message);
    void RegisterMessage(uint32_t type, transport::MessageProcessor proc);
    void UnRegisterMessage(uint32_t type);
    void Init();
    void Destroy();
    dht::BaseDhtPtr GetDht(const std::string& dht_key, bool universal);
    void RouteByUniversal(transport::protobuf::Header& header);

private:
    Route();
    ~Route();
    void HandleMessage(transport::protobuf::Header& header);
    void HandleDhtMessage(transport::protobuf::Header& header);
    void Broadcast(transport::protobuf::Header& header);

    transport::MessageProcessor message_processor_[common::kLegoMaxMessageTypeCount];
    broadcast::BroadcastPtr broadcast_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(Route);
};

}  // namespace network

}  // namespace lego
