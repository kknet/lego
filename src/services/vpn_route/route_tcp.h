#pragma once

#include <memory>
#include <vector>
#include <thread>

#include "uv/uv.h"
#include "services/vpn_route/vpn_route_utils.h"

namespace lego {

namespace vpnroute {

class TcpRoute {
public:
    static TcpRoute* Instance();
    int Init(const std::string& local_ip, uint16_t port);
    uv_loop_t* server_loop() {
        return server_loop_;
    }

    uv_loop_t* client_loop() {
        return client_loop_;
    }

private:
    typedef std::vector<uv_buf_t> ListType;

    TcpRoute();
    ~TcpRoute();

    static void AllocBuffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
    static void EchoRead(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
    static void ClientOnWriteEnd(uv_write_t *req, int status);
    static void OnNewConnection(uv_stream_t *server, int status);
    static void CreateRemote(
            const std::string& remote_ip,
            uint16_t remote_port,
            uv_tcp_t* client,
            char* left_data,
            uint32_t left_len);
    static void RemoteEchoRead(uv_stream_t *server, ssize_t nread, const uv_buf_t* buf);
    static void RemoteAllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void RemoteOnWriteEnd(uv_write_t *req, int status);
    static void RemoteOnWriteConnectEnd(uv_write_t *req, int status);
    static void RemoteOnConnect(uv_connect_t * req, int status);

    static void CloseClient(uv_handle_t* handle);
    static void CloseRemote(uv_handle_t* handle);

    int CreateServer(const std::string& local_ip, uint16_t port);
    void StartUv();

    static const uint32_t kBackblog = 128u;
    static const uint32_t kRelaySkipHeader = 7u;
    static const uint32_t kMaxReservedBuf = 128u;

    uv_loop_t* server_loop_;
    uv_loop_t* client_loop_;
    uv_tcp_t server_;
    std::shared_ptr<std::thread> uv_thread_{ nullptr };

    DISALLOW_COPY_AND_ASSIGN(TcpRoute);

};

}  // namespace vpnroute

}  // namespace lego
