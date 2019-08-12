#pragma once

#include "transport/transport.h"
#include "httplib.h"

namespace lego {

namespace transport {

class HttpTransport : public Transport {
public:
    HttpTransport();
    virtual ~HttpTransport();
    virtual int Init();
    virtual int Start(bool hold);
    virtual void Stop();
    virtual int Send(
            const std::string& ip,
            uint16_t port,
            uint32_t ttl,
            transport::protobuf::Header& message);
    virtual int SendToLocal(transport::protobuf::Header& message);
    virtual int GetSocket();

private:
    httplib::Server http_svr_;

    DISALLOW_COPY_AND_ASSIGN(HttpTransport);
};

}  // namespace transport

}  // namespace lego
