#pragma once

#include <memory>

#include "uv/uv.h"
#include "services/vpn_route/vpn_route_utils.h"

namespace lego {

namespace vpnroute {

struct ServerInfo {
    uv_tcp_t* remote_socket;
    uv_connect_t* remote_connect;
    uv_tcp_t* client;
};
typedef std::shared_ptr<ServerInfo> ServerInfoPtr;

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
    TcpRoute();
    ~TcpRoute();

    static void AllocBuffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
    static void EchoRead(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
    static void EchoWrite(uv_write_t *req, int status);
    static void OnNewConnection(uv_stream_t *server, int status);
    static int CreateRemote(
            const std::string& remote_ip,
            uint16_t remote_port,
            ServerInfo* svr_info);
    static void RemoteEchoRead(uv_stream_t *server, ssize_t nread, const uv_buf_t* buf);
    static void RemoteAllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
    static void RemoteOnWriteEnd(uv_write_t *req, int status);
    static void RemoteOnConnect(uv_connect_t * req, int status);

    static void CloseClient(uv_handle_t* handle);

    int CreateServer(const std::string& local_ip, uint16_t port);

    static const uint32_t kBackblog = 128;

    uv_loop_t* server_loop_;
    uv_loop_t* client_loop_;
    uv_tcp_t server_;

    DISALLOW_COPY_AND_ASSIGN(TcpRoute);

};

}  // namespace vpnroute

}  // namespace lego
