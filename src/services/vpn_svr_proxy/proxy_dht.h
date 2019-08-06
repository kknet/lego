#pragma once

#include "dht/base_dht.h"
#include "dht/node.h"
#include "services/proto/service.pb.h"

namespace lego {

namespace vpn {

class ProxyDht : public dht::BaseDht {
public:
    ProxyDht(transport::TransportPtr& transport, dht::NodePtr& local_node);
    virtual ~ProxyDht();
    virtual void HandleMessage(transport::protobuf::Header& msg);

private:
    void HandleGetSocksRequest(
            transport::protobuf::Header& msg,
            service::protobuf::ServiceMessage& svr_msg);

    DISALLOW_COPY_AND_ASSIGN(ProxyDht);
};

}  // namespace vpn

}  // namespace lego
