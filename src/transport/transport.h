#pragma once

#include "common/utils.h"
#include "transport/proto/transport.pb.h"

namespace lego {

namespace transport {

class Transport {
public:
    virtual int Init() = 0;
    virtual int Start(bool hold) = 0;
    virtual void Stop() = 0;
    virtual int Send(
            const std::string& ip,
            uint16_t port,
            uint32_t ttl,
            transport::protobuf::Header& message) = 0;
    virtual int SendToLocal(transport::protobuf::Header& message) = 0;
    virtual int GetSocket() = 0;

protected:
    Transport() {}
    virtual ~Transport() {}

private:

    DISALLOW_COPY_AND_ASSIGN(Transport);
};

typedef std::shared_ptr<Transport> TransportPtr;

}  // namespace transport

}  // namespace lego
