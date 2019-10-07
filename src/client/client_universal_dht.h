#pragma once

#include "dht/base_dht.h"
#include "transport/transport.h"

namespace lego {

namespace client {

class ClientUniversalDht : public dht::BaseDht {
public:
    ClientUniversalDht(transport::TransportPtr& transport_ptr, dht::NodePtr& local_node);
    virtual ~ClientUniversalDht();

    virtual void HandleMessage(transport::protobuf::Header& msg);
    virtual void SetFrequently(transport::protobuf::Header& msg);

private:

    DISALLOW_COPY_AND_ASSIGN(ClientUniversalDht);
};

typedef std::shared_ptr<ClientUniversalDht> ClientUniversalDhtPtr;

}  // namespace client

}  // namespace lego
