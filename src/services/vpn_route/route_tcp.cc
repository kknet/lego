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

void TcpRoute::ClientOnWriteEnd(uv_write_t* req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
        CloseClient((uv_handle_t*)req->handle);
    }
    free(req);
}

void TcpRoute::EchoRead(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
    if (nread < 0) {
        CloseClient((uv_handle_t*)client);
    } else if (nread > 0) {
        uint8_t head_tag = *(uint8_t*)buf->base;
        ServerInfo* svr_info = (ServerInfo*)client->u.reserved[0];
        if (svr_info == NULL && head_tag == 1) {
            if (nread >= kRelaySkipHeader) {
                char host[255] = { 0 };
                uint16_t port = 0;
                inet_ntop(AF_INET, (const void *)(buf->base + 1), host, INET_ADDRSTRLEN);
                port = load16_be(buf->base + 5);
                std::cout << "connect remote server: " << host << ":" << port << std::endl;
                CreateRemote(host, port, (uv_tcp_t*)client, buf->base, nread);
                return;  // don't free buf
            } else {
                CloseClient((uv_handle_t*)client);
            }
        } else {
            if (svr_info == NULL) {
                return;
            }

            uv_tcp_t* remote_tcp = (uv_tcp_t*)svr_info->remote_socket;
            if (remote_tcp == NULL) {
                return;
            }

            if (remote_tcp->u.reserved[1] == NULL) {
                uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
                int buf_count = 1;
                uv_stream_t* remote_stream = (uv_stream_t*)svr_info->remote_socket;
                uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
                uv_write(req, remote_stream, &wrbuf, buf_count, TcpRoute::RemoteOnWriteEnd);
            }
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

void TcpRoute::RemoteEchoRead(uv_stream_t* server, ssize_t nread, const uv_buf_t* buf) {
    do  {
        if (nread < 0) {
            std::cout << "remote read error." << std::endl;
            CloseRemote((uv_handle_t*)server);
            break;
        }

        uv_tcp_t* svr_tcp = (uv_tcp_t*)server;
        ServerInfo* svr_info = (ServerInfo*)(svr_tcp->u.reserved[0]);
        if (svr_info == NULL) {
            std::cout << "remote read error." << std::endl;
            CloseRemote((uv_handle_t*)server);
            break;
        }

        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        int buf_count = 1;
        uv_stream_t* client_stream = (uv_stream_t*)svr_info->client;
        uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
        uv_write(req, client_stream, &wrbuf, buf_count, TcpRoute::ClientOnWriteEnd);
        std::cout << "write to client: " << nread << std::endl;
    } while (0);

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
        std::cout << "remote write error." << std::endl;
        CloseRemote((uv_handle_t*)req->handle);
    }
    free(req);
    // uv_read_start(req->handle, TcpRoute::RemoteAllocBuffer, TcpRoute::RemoteEchoRead);
}

void TcpRoute::RemoteOnConnect(uv_connect_t* req, int status) {
    uv_tcp_t* remote_tcp = (uv_tcp_t*)req->handle;
    uint32_t* left_len = (uint32_t*)remote_tcp->u.reserved[2];
    if (status < 0 || remote_tcp->u.reserved[2] == NULL || remote_tcp->u.reserved[1] == NULL) {
        fprintf(stderr, "error on_write_end");
        if (remote_tcp->u.reserved[2] != NULL) {
            delete left_len;
        }

        if (remote_tcp->u.reserved[1] != NULL) {
            free(remote_tcp->u.reserved[1]);
        }
        remote_tcp->u.reserved[1] = NULL;
        remote_tcp->u.reserved[2] = NULL;
        return;
    }

    std::cout << "remote connect and now write more data: " << status << ":" << *left_len << std::endl;
    if (*left_len > kRelaySkipHeader && *left_len < 1024) {
        char buffer[1024 * 16];
        uv_buf_t buf = uv_buf_init(buffer, sizeof(buffer));
        buf.len = *left_len - kRelaySkipHeader;
        buf.base = ((char*)remote_tcp->u.reserved[1]) + kRelaySkipHeader;
        uv_stream_t* tcp = req->handle;
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        int buf_count = 1;
        uv_write(req, tcp, &buf, buf_count, TcpRoute::RemoteOnWriteEnd);
    }
    delete left_len;
    free(remote_tcp->u.reserved[1]);
    remote_tcp->u.reserved[1] = NULL;
    remote_tcp->u.reserved[2] = NULL;
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
    std::cout << "should write left data: " << left_len << ":" << (left_len - kRelaySkipHeader) << std::endl;
    uv_tcp_connect(
            svr_info->remote_connect,
            svr_info->remote_socket,
            (const struct sockaddr*)&dest,
            TcpRoute::RemoteOnConnect);
}

void TcpRoute::OnNewConnection(uv_stream_t* server, int status) {
    if (status < 0) {
        std::cout << "new connection error." << std::endl;
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

    uv_tcp_t* client = (uv_tcp_t*)handle;
    if (client->u.reserved[0] != NULL) {
        std::cout << "closed remote." << std::endl;
        ServerInfo* svr_info = (ServerInfo*)client->u.reserved[0];
        free(svr_info->remote_connect);
        delete svr_info;
        client->u.reserved[0] = NULL;
    }

    if (uv_is_closing(handle) == 0) {
        std::cout << "closed client." << std::endl;
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
    server_loop_ = client_loop_;
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
    client_loop_ = uv_loop_new();
    if (CreateServer(local_ip, port) != kVpnRouteSuccess) {
        return kVpnRouteError;
    }
    return kVpnRouteSuccess;
}

}  // namespace vpnroute

}  // namespace lego
