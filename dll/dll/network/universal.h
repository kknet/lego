#pragma once

#include <unordered_set>
#include <vector>

#include "transport/transport.h"
#include "dht/base_dht.h"
#include "dht/node.h"
#include "network/proto/network.pb.h"

namespace lego {

namespace network {

class Universal : public dht::BaseDht {
public:
    Universal(transport::TransportPtr& transport_ptr, dht::NodePtr& local_node);
    virtual ~Universal();
    virtual int Init();
    virtual int Destroy();
    virtual bool CheckDestination(const std::string& des_dht_key, bool closest);
    virtual void HandleMessage(transport::protobuf::Header& msg);
    virtual void SetFrequently(transport::protobuf::Header& msg);
    virtual bool IsUniversal() { return true; }

    void AddNetworkId(uint32_t network_id);
    void RemoveNetworkId(uint32_t network_id);
    bool HasNetworkId(uint32_t network_id);
    std::vector<dht::NodePtr> LocalGetNetworkNodes(uint32_t network_id, uint32_t count);
    std::vector<dht::NodePtr> RemoteGetNetworkNodes(uint32_t network_id, uint32_t count);
    std::vector<dht::NodePtr> LocalGetNetworkNodes(
            uint32_t network_id,
            uint8_t country,
            uint32_t count);
    std::vector<dht::NodePtr> RemoteGetNetworkNodes(
            uint32_t network_id,
            uint8_t country,
            uint32_t count);

private:
    void ProcessGetNetworkNodesRequest(
            transport::protobuf::Header& header,
            protobuf::NetworkMessage& network_msg);
    void ProcessGetNetworkNodesResponse(
            transport::protobuf::Header& header,
            protobuf::NetworkMessage& network_msg);


    bool* universal_ids_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(Universal);
};

}  // namespace network

}  //namespace lego
