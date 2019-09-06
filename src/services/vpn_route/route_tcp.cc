#include "services/vpn_route/route_tcp.h"

namespace lego {

namespace vpnroute {

void TcpRoute::AllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void TcpRoute::EchoWrite(uv_write_t* req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
        CloseClient((uv_handle_t*)req->handle);
    }
    free(req);
}

void TcpRoute::EchoRead(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
            CloseClient((uv_handle_t*)client);
        }
    } else if (nread > 0) {
        uv_write_t* req = (uv_write_t* ) malloc(sizeof(uv_write_t));
        uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
        uv_write(req, client, &wrbuf, 1, TcpRoute::EchoWrite);
    }

    if (buf->base) {
        free(buf->base);
    }
}

void TcpRoute::RemoteEchoRead(uv_stream_t* server, ssize_t nread, const uv_buf_t* buf) {
    if (nread == -1) {
        fprintf(stderr, "error echo_read");
        return;
    }

    printf("result: %s\n", buf->base);
}

void TcpRoute::RemoteAllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void TcpRoute::RemoteOnWriteEnd(uv_write_t* req, int status) {
    if (status == -1) {
        fprintf(stderr, "error on_write_end");
        return;
    }
    uv_read_start(req->handle, TcpRoute::RemoteAllocBuffer, TcpRoute::RemoteEchoRead);
}

void TcpRoute::RemoteOnConnect(uv_connect_t* req, int status) {
    uv_tcp_t* remote_tcp = (uv_tcp_t*)req->handle;
    if (status == -1) {
        fprintf(stderr, "error on_write_end");
        return;
    }
    char buffer[100];
    uv_buf_t buf = uv_buf_init(buffer, sizeof(buffer));
    char* message = "hello";
    buf.len = strlen(message);
    buf.base = message;
    uv_stream_t* tcp = req->handle;
    uv_write_t write_req;
    int buf_count = 1;
    uv_write(&write_req, tcp, &buf, buf_count, TcpRoute::RemoteOnWriteEnd);
}

int TcpRoute::CreateRemote(
        const std::string& remote_ip,
        uint16_t remote_port,
        ServerInfo* svr_info) {
    svr_info->remote_socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(TcpRoute::Instance()->client_loop(), svr_info->remote_socket);
    svr_info->remote_connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    struct sockaddr_in dest;
    uv_ip4_addr(remote_ip.c_str(), remote_port, &dest);
    uv_tcp_connect(
            svr_info->remote_connect,
            svr_info->remote_socket,
            (const struct sockaddr*)&dest,
            TcpRoute::RemoteOnConnect);
}

void TcpRoute::OnNewConnection(uv_stream_t* server, int status) {
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        return;
    }

    uv_tcp_t* client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    client->u.reserved[0] = NULL;
    uv_tcp_init(TcpRoute::Instance()->server_loop(), client);
    if (uv_accept(server, (uv_stream_t*)client) == 0) {
        uv_read_start((uv_stream_t*)client, TcpRoute::AllocBuffer, TcpRoute::EchoRead);
    } else {
        uv_close((uv_handle_t*)client, NULL);
    }
    ServerInfo* svr_info = new  ServerInfo();
    client->u.reserved[0] = svr_info;
}

void TcpRoute::CloseClient(uv_handle_t* handle) {
    std::cout << "close client." << std::endl;
    uv_tcp_t* client = (uv_tcp_t*)handle;
    if (client->u.reserved[0] != NULL) {
        delete client->u.reserved[0];
        client->u.reserved[0] = NULL;
    }
    uv_close((uv_handle_t*)handle, NULL);
}

TcpRoute* TcpRoute::Instance() {
    static TcpRoute ins;
    return &ins;
}

TcpRoute::TcpRoute() {}

TcpRoute::~TcpRoute() {}

int TcpRoute::CreateServer(const std::string& local_ip, uint16_t port) {
    server_loop_ = uv_default_loop();
    if (uv_tcp_init(server_loop_, &server_) != 0) {
        return kVpnRouteError;
    }

    struct sockaddr_in bind_addr;
    int res = uv_ip4_addr(local_ip.c_str(), port, &bind_addr);
    if (res != 0) {
        return kVpnRouteError;
    }

    res = uv_tcp_bind(&server_, (const struct sockaddr*)&bind_addr, 0);
    if (res != 0) {
        return kVpnRouteError;
    }

    int r = uv_listen((uv_stream_t*)&server_, kBackblog, TcpRoute::OnNewConnection);
    if (r) {
        fprintf(stderr, "error uv_listen");
        return kVpnRouteError;
    }

    uv_run(server_loop_, UV_RUN_DEFAULT);
    return kVpnRouteSuccess;
}

int TcpRoute::Init(const std::string& local_ip, uint16_t port) {
    if (CreateServer(local_ip, port) != kVpnRouteSuccess) {
        return kVpnRouteError;
    }
    return kVpnRouteSuccess;
}

}  // namespace vpnroute

}  // namespace lego
