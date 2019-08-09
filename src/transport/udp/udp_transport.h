#pragma once

#include <string>
#include <memory>
#include <thread>

#include "uv/uv.h"

#include "common/log.h"
#include "transport/transport.h"

namespace lego {

namespace transport {

class UdpTransport : public Transport {
public:
    UdpTransport(
            const std::string& ip,
            uint16_t port,
            uint32_t send_buffer_size,
            uint32_t recv_buffer_size);
    virtual ~UdpTransport();
    virtual int Init();
    virtual int Start(bool hold);
    virtual void Stop();
    virtual int Send(
            const std::string& ip,
            uint16_t port,
            uint32_t ttl,
            transport::protobuf::Header& message);
    virtual int SendToLocal(transport::protobuf::Header& message);
    virtual int GetSocket() {
        return socket_;
    }

private:
    void Run();
    void SetSocketOption();
    uint64_t GetMessageHash(transport::protobuf::Header& message);

    static const uint32_t kDefaultTtl = 99u;

    uv_loop_t* uv_loop_{ nullptr };
    uv_udp_t uv_udp_;
    std::string ip_;
    uint16_t port_{ 0 };
    uint32_t send_buf_size_{ 0 };
    uint32_t recv_buf_size_{ 0 };
    std::shared_ptr<std::thread> run_thread_{ nullptr };
    bool destroy_{ false };
    uv_os_sock_t socket_;
    std::mutex ttl_mutex_;

    DISALLOW_COPY_AND_ASSIGN(UdpTransport);
};

}  // namespace transport

}  // namespace lego
