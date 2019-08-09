#include "transport/udp/udp_transport.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <functional>
#include <atomic>

#include "common/log.h"
#include "common/hash.h"
#include "common/encode.h"
#include "common/global_info.h"
#include "transport/transport_utils.h"
#include "transport/multi_thread.h"

namespace lego {

namespace transport {

static void Startup(void) {
#ifdef _WIN32
    struct WSAData wsa_data;
    int r = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    assert(r == 0);
#endif
}

static uv_os_sock_t CreateUdpSocket(void) {
  uv_os_sock_t sock;
  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
#ifdef _WIN32
  assert(sock != INVALID_SOCKET);
#else
  assert(sock >= 0);
#endif

#ifndef _WIN32
  {
    /* Allow reuse of the port. */
    int yes = 1;
    int r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    assert(r == 0);
  }
#endif
  return sock;
}

static void CloseSocket(uv_os_sock_t sock) {
#ifdef _WIN32
  closesocket(sock);
#else
  close(sock);
#endif
}

static void AllocCallback(uv_handle_t* handle, size_t size, uv_buf_t* buf) {
    static char slab[65536];
    buf->base = slab;
    buf->len = sizeof(slab);;
}

static void ReceiveCallback(
        uv_udp_t* handle,
        ssize_t nread,
        const uv_buf_t* rcvbuf,
        const struct sockaddr* addr,
        unsigned flags) {
    if (handle == nullptr || rcvbuf == nullptr || addr == nullptr) {
        return;
    }

    if (nread <= 0) {
        return;
    }
    struct sockaddr_in *sock = (struct sockaddr_in*)addr;
    char ip[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &sock->sin_addr, ip, sizeof(ip));
    int from_port = ntohs(sock->sin_port);
    MultiThreadHandler::Instance()->HandleMessage(
            std::string(ip),
            from_port,
            rcvbuf->base, nread);
#ifdef TEST_TRANSPORT_PERFOMANCE
    static std::atomic<uint32_t> rcv_cnt;
    ++rcv_cnt;
    if (rcv_cnt % 20000 == 0) {
        std::cout << "recv msg." << (uint32_t)rcv_cnt << std::endl;
    }
#endif
}

UdpTransport::UdpTransport(
        const std::string& ip,
        uint16_t port,
        uint32_t send_buffer_size,
        uint32_t recv_buffer_size)
        : ip_(ip),
          port_(port),
          send_buf_size_(send_buffer_size),
          recv_buf_size_(recv_buffer_size) {
    assert(!ip_.empty());
    assert(send_buf_size_ > 0);
    assert(recv_buf_size_ > 0);
}

UdpTransport::~UdpTransport() {
    Stop();
}

int UdpTransport::Start(bool hold) {
    if (hold) {
        Run();
    } else {
        run_thread_ = std::make_shared<std::thread>(std::bind(&UdpTransport::Run, this));
        run_thread_->detach();
    }
    return kTransportSuccess;
}

void UdpTransport::Stop() {
    destroy_ = true;
    if (uv_loop_ != nullptr) {
        uv_stop(uv_loop_);
        uv_loop_close(uv_loop_);
        uv_loop_ = nullptr;
    }
    CloseSocket(socket_);
}

int UdpTransport::Init() {
    uv_loop_ = uv_default_loop();
    if (uv_loop_ == nullptr) {
        TRANSPORT_ERROR("create uv loop failed!");
        return kTransportError;
    }

    struct sockaddr_in addr;
    if (uv_ip4_addr(ip_.c_str(), port_, &addr) != 0) {
        TRANSPORT_ERROR("create uv ipv4 addr failed!");
        return kTransportError;
    }

    Startup();
    socket_ = CreateUdpSocket();

    if (uv_udp_init(uv_loop_, &uv_udp_) != 0) {
        TRANSPORT_ERROR("init udp failed!");
        return kTransportError;
    }

    if (uv_udp_open(&uv_udp_, socket_) != 0) {
        TRANSPORT_ERROR("uv_udp_open failed!");
        return kTransportError;
    }

    SetSocketOption();
    if (uv_udp_bind(&uv_udp_, (const struct sockaddr*) &addr, UV_UDP_REUSEADDR) != 0) {
        TRANSPORT_ERROR("udp bind addr failed!");
        return kTransportError;
    }

    if (uv_udp_recv_start(
            &uv_udp_,
            AllocCallback,
            ReceiveCallback) != 0) {
        TRANSPORT_ERROR("start udp to receive data failed!");
        return kTransportError;
    }

    return kTransportSuccess;
}

void UdpTransport::Run() {
    if (uv_run(uv_loop_, UV_RUN_DEFAULT) != 0) {
        TRANSPORT_ERROR("uv run failed!");
        assert(false);
    }
}

int UdpTransport::SendToLocal(transport::protobuf::Header& message) {
    message.clear_broadcast();
    MultiThreadHandler::Instance()->HandleMessage(message);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("UdpTransport::SendToLocal", message);
    return kTransportSuccess;
}

int UdpTransport::Send(
        const std::string& ip,
        uint16_t port,
        uint32_t ttl,
        transport::protobuf::Header& proto) {
    struct sockaddr_in addr;
    if (uv_ip4_addr(ip.c_str(), port, &addr) != 0) {
        TRANSPORT_ERROR("create uv ipv4 addr failed!");
        return kTransportError;
    }

    // must clear
    proto.clear_from_ip();
    proto.clear_from_port();
    proto.clear_to_ip();
    proto.clear_to_port();
    proto.clear_handled();
    proto.clear_client_proxy();
    proto.clear_client_handled();
    if (!proto.has_hash()) {
        proto.set_hash(GetMessageHash(proto));
    }

    auto message = proto.SerializeAsString();
    assert(message.size() <= 6500);
    static const uint32_t kSendBufCount = 2u;
    uv_buf_t buf[kSendBufCount];
    TransportHeader header;
    header.size = message.size();
    buf[0] = uv_buf_init((char*)&header, sizeof(TransportHeader));
    buf[1] = uv_buf_init((char*)message.c_str(), message.size());
    {
        std::lock_guard<std::mutex> guard(ttl_mutex_);
        if (ttl != 0) {
            uv_udp_set_ttl(&uv_udp_, ttl);
        }
#ifdef LEGO_TRACE_MESSAGE
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(
                std::string("udp sent ") + ip + ":" + std::to_string(port),
                proto);
#endif // LEGO_TRACE_MESSAGE
        int res = uv_udp_try_send(&uv_udp_, buf, kSendBufCount, (const struct sockaddr*)&addr);
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(std::string("udp send res: ") + std::to_string(res), proto);
        if (ttl != 0) {
            uv_udp_set_ttl(&uv_udp_, kDefaultTtl);
        }
    }
    return kTransportSuccess;
}

void UdpTransport::SetSocketOption() {
    setsockopt(
            socket_,
            SOL_SOCKET,
            SO_RCVBUF,
            (const char *)&recv_buf_size_,
            sizeof(recv_buf_size_));
    setsockopt(
            socket_,
            SOL_SOCKET,
            SO_SNDBUF,
            (const char *)&send_buf_size_,
            sizeof(send_buf_size_));
}

uint64_t UdpTransport::GetMessageHash(transport::protobuf::Header& message) {
    auto hash = common::Hash::Hash64(
            message.src_node_id() + std::to_string(message.id()) + message.data());
    return hash;
}

}  // namespace transport

}  // namespace lego