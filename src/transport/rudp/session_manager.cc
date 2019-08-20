#include "transport/rudp/session_manager.h"

#include "transport/multi_thread.h"

namespace lego {

namespace transport {

static const uint32_t kKcpSessionDefaultNum = 0x11223344u;
transport::UdpTransportPtr SessionManager::udp_transport_ = nullptr;

SessionManager* SessionManager::Instance() {
	static SessionManager ins;
	return &ins;
}

void SessionManager::Send(
		const std::string& ip,
		uint16_t port,
		transport::protobuf::Header& message) {
	auto session_ptr = GetSession(ip, port);
	assert(session_ptr != nullptr);
	assert(session_ptr->kcp != nullptr);
	auto buf = message.SerializeAsString();
	ikcp_send(session_ptr->kcp.get(), buf.c_str(), buf.size());
}

void SessionManager::Recv(
		const std::string& ip,
		uint16_t port,
		const char* buf,
		uint32_t size) {
	auto session_ptr = GetSession(ip, port);
	assert(session_ptr != nullptr);
	assert(session_ptr->kcp != nullptr);
	ikcp_input(session_ptr->kcp.get(), buf, size);
	auto kcp_recv = ikcp_recv(session_ptr->kcp.get(), recv_buf_, kKcpRecvBuffSize);
	if (kcp_recv > 0) {
		// call message handler
		MultiThreadHandler::Instance()->HandleRemoteMessage(
				ip,
				port,
				recv_buf_,
				kcp_recv);
	}
}

int SessionManager::SendWithUdp(const char *buf, int len, ikcpcb *kcp, void *user) {
	Endpoint* endpoint = static_cast<Endpoint*>(user);
	udp_transport_->SendKcpBuf(endpoint->ip, endpoint->port, buf, len);
	return 0;
}

SessionItemPtr SessionManager::GetSession(const std::string& ip, uint16_t port) {
	auto endpoint = std::make_shared<Endpoint>(ip, port);
	auto session_ptr = session_map_ptr_;
	if (session_ptr != nullptr) {
		auto iter = session_ptr->find(*endpoint);
		if (iter != session_ptr->end()) {
			return iter->second;
		}
	}

	std::lock_guard<std::mutex> guard(session_map_mutex_);
	auto iter = session_map_.find(*endpoint);
	if (iter != session_map_.end()) {
		return iter->second;
	}

	auto kcp = std::shared_ptr<ikcpcb>(
			ikcp_create(kKcpSessionDefaultNum, (void*)endpoint.get()),
			ikcp_release);
	kcp->output = SessionManager::SendWithUdp;
	ikcp_wndsize(kcp.get(), kKcpSendWindowSize, kKcpRecvWindowSize);
	ikcp_nodelay(kcp.get(), 1, 10, 2, 1);
	kcp->rx_minrto = 10;
	kcp->fastresend = 1;
	auto session_item = std::make_shared<SessionItem>(kcp, endpoint);
	session_map_[*endpoint] = session_item;
	session_map_ptr_ = std::make_shared<SessionMap>(session_map_);
	return session_item;
}

void SessionManager::RemoveSession(const std::string& ip, uint16_t port) {
	std::lock_guard<std::mutex> guard(session_map_mutex_);
	Endpoint endpoint(ip, port);
	auto iter = session_map_.find(endpoint);
	if (iter == session_map_.end()) {
		return;
	}
	session_map_.erase(iter);
	session_map_ptr_ = std::make_shared<SessionMap>(session_map_);
}

void SessionManager::KcpUpdate() {
	while (!destroy_) {
		auto session_map_ptr = session_map_ptr_;
		if (session_map_ptr != nullptr) {
			for (auto iter = session_map_ptr->begin(); iter != session_map_ptr->end(); ++iter) {
				auto now = common::iclock();
				if (now >= iter->second->next_update) {
					ikcp_update(iter->second->kcp.get(), now);
					iter->second->next_update = ikcp_check(iter->second->kcp.get(), now);
				}
			}
		}

		std::this_thread::sleep_for(std::chrono::microseconds(10000ull));
	}
}

SessionManager::SessionManager() : kcp_update_thread_(&SessionManager::KcpUpdate, this) {
	recv_buf_ = new char[kKcpRecvBuffSize];
}

SessionManager::~SessionManager() {
	destroy_ = true;
	if (recv_buf_ != nullptr) {
		delete []recv_buf_;
	}
}

}  // namespace transport

}  // namespace lego
