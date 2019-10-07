#pragma once

#include "transport/endpoint.h"
#include <unordered_map>
#include <atomic>
#include <memory>

#include "kcp/ikcp.h"
#include "transport/udp/udp_transport.h"

namespace lego {

namespace transport {

typedef std::shared_ptr<ikcpcb> KcpPtr;

struct SessionItem {
	SessionItem(KcpPtr& in_kcp, std::shared_ptr<Endpoint>& e)
			: kcp(in_kcp), endpoint(e), next_update(0) {}
	KcpPtr kcp;
	std::shared_ptr<Endpoint> endpoint;
	uint32_t next_update;
};
typedef std::shared_ptr<SessionItem> SessionItemPtr;

class SessionManager {
public:
	static SessionManager* Instance();
	void SetUdpTransport(transport::UdpTransportPtr& udp_transport) {
		udp_transport_ = udp_transport;
	}
	void Send(const std::string& ip, uint16_t port, transport::protobuf::Header& message);
	void Recv(const std::string& ip, uint16_t port, const char* buf, uint32_t size);
	SessionItemPtr GetSession(const std::string& ip, uint16_t port);
	void RemoveSession(const std::string& ip, uint16_t port);

private:
	SessionManager();
	~SessionManager();
	static int SendWithUdp(const char *buf, int len, ikcpcb *kcp, void *user);
	void KcpUpdate();

	static transport::UdpTransportPtr udp_transport_;
	static const uint32_t kKcpRecvBuffSize = 10 * 1024 * 1024;

	typedef std::unordered_map<Endpoint, SessionItemPtr> SessionMap;
	SessionMap session_map_;
	std::mutex session_map_mutex_;
	std::shared_ptr<SessionMap> session_map_ptr_{ nullptr };
	std::thread kcp_update_thread_;
	bool destroy_{ false };
	char* recv_buf_{ nullptr };

	DISALLOW_COPY_AND_ASSIGN(SessionManager);
};

}  // namespace transport

}  // namespace lego
