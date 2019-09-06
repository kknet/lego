#include "services/vpn_route/route_tcp.h"

namespace lego {

namespace vpnroute {

static uint16_t load16_be(const void *s) {
    const uint8_t *in = (const uint8_t *)s;
    return ((uint16_t)in[0] << 8) | ((uint16_t)in[1]);
}

void TcpRoute::AllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void TcpRoute::EchoWrite(uv_write_t* req, int status) {
    std::cout << "echo write." << status << std::endl;
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
        CloseClient((uv_handle_t*)req->handle);
    }
    free(req);
}

void TcpRoute::EchoRead(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
    std::cout << "echo read." << nread << std::endl;
    if (nread < 0) {
        CloseClient((uv_handle_t*)client);
    } else if (nread > 0) {
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        uint8_t head_tag = *(uint8_t*)buf->base;
        if (head_tag == 1) {
            if (nread >= 7) {
                char host[255] = { 0 };
                uint16_t port = 0;
                inet_ntop(AF_INET, (const void *)(buf->base + 1), host, INET_ADDRSTRLEN);
                port = ntohs(load16_be(buf->base + 5));
                std::cout << "connect remote server: " << host << ":" << port << std::endl;
                CreateRemote(host, port, (uv_tcp_t*)client, buf->base, nread);
                return;  // don't free buf
            } else {
                CloseClient((uv_handle_t*)client);
            }
        } else {
            uv_buf_t wrbuf = uv_buf_init(buf->base + 1, nread - 1);
            uv_write(req, client, &wrbuf, 1, TcpRoute::EchoWrite);
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

void TcpRoute::RemoteEchoRead(uv_stream_t* server, ssize_t nread, const uv_buf_t* buf) {
    if (nread < 0) {
        fprintf(stderr, "error echo_read");
        CloseRemote((uv_handle_t*)server);
        return;
    }

    printf("result: %s\n", buf->base);
    if (buf->base) {
        free(buf->base);
    }
}

void TcpRoute::RemoteAllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

void TcpRoute::RemoteOnWriteEnd(uv_write_t* req, int status) {
    if (status == -1) {
        fprintf(stderr, "error on_write_end");
        CloseRemote((uv_handle_t*)req->handle);
        return;
    }
    uv_read_start(req->handle, TcpRoute::RemoteAllocBuffer, TcpRoute::RemoteEchoRead);
}

void TcpRoute::RemoteOnConnect(uv_connect_t* req, int status) {
    uv_tcp_t* remote_tcp = (uv_tcp_t*)req->handle;
    uint32_t* left_len = (uint32_t*)remote_tcp->u.reserved[2];
    if (status < 0) {
        fprintf(stderr, "error on_write_end");
        CloseRemote((uv_handle_t*)req->handle);
        delete left_len;
        free(remote_tcp->u.reserved[1]);
        return;
    }
    if (*left_len > 7) {
        char buffer[1024];
        uv_buf_t buf = uv_buf_init(buffer, sizeof(buffer));
        buf.len = *left_len - 7;
        buf.base = ((char*)remote_tcp->u.reserved[1]) + 7;
        uv_stream_t* tcp = req->handle;
        uv_write_t write_req;
        int buf_count = 1;
        uv_write(&write_req, tcp, &buf, buf_count, TcpRoute::RemoteOnWriteEnd);
    }
    delete left_len;
    free(remote_tcp->u.reserved[1]);
}

void TcpRoute::CreateRemote(
        const std::string& remote_ip,
        uint16_t remote_port,
        uv_tcp_t* client,
        char* left_data,
        uint32_t left_len) {
    ServerInfo* svr_info = new ServerInfo();
    svr_info->remote_socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(TcpRoute::Instance()->client_loop(), svr_info->remote_socket);
    svr_info->remote_connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    struct sockaddr_in dest;
    uv_ip4_addr(remote_ip.c_str(), remote_port, &dest);
    client->u.reserved[0] = svr_info;
    svr_info->client = client;
    svr_info->remote_socket->u.reserved[0] = svr_info;
    uint32_t* left_int = new uint32_t;
    *left_int = left_len;
    svr_info->remote_socket->u.reserved[1] = left_data;
    svr_info->remote_socket->u.reserved[2] = left_int;
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
}

void TcpRoute::CloseClient(uv_handle_t* handle) {
    if (handle == NULL) {
        return;
    }

    std::cout << "close client." << std::endl;
    uv_tcp_t* client = (uv_tcp_t*)handle;
    if (client->u.reserved[0] != NULL) {
        ServerInfo* svr_info = (ServerInfo*)client->u.reserved[0];
        free(svr_info->remote_connect);
        delete svr_info;
        client->u.reserved[0] = NULL;
    }

    if (uv_is_closing(handle) == 0) {
        uv_close(handle, NULL);
    }
}

void TcpRoute::CloseRemote(uv_handle_t* handle) {
    if (handle == NULL) {
        return;
    }

    if (uv_is_closing(handle) == 0) {
        uv_close(handle, NULL);
    }

    ServerInfo* svr_info = (ServerInfo*)((uv_tcp_t*)handle)->u.reserved[0];
    CloseClient((uv_handle_t*)svr_info->client);
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
