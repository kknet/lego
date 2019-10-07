#pragma once

#include "network/universal.h"

namespace lego {

namespace client {

class ClientUniversalDht : public network::Uniersal {
public:
    virtual void HandleMessage(transport::protobuf::Header& msg);
    virtual void SetFrequently(transport::protobuf::Header& msg);

private:

    DISALLOW_COPY_AND_ASSIGN(ClientUniversalDht);
};

}  // namespace client

}  // namespace lego
