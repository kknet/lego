#include "stdafx.h"
#include "transport/rudp/rudp.h"
#include "transport/udp/udp_transport.h"
#include "transport/endpoint.h"

namespace lego {

namespace transport {

static transport::UdpTransportPtr udp_transport_;

Rudp::Rudp() {}

Rudp::~Rudp() {}

int Rudp::Init() {
	return kTransportSuccess;
}

int Rudp::Start(bool hold) {
	return kTransportSuccess;
}

void Rudp::Stop() {
}

int Rudp::Send(
		const std::string& ip,
		uint16_t port,
		uint32_t ttl,
		transport::protobuf::Header& message) {
	return kTransportSuccess;
}

int Rudp::SendToLocal(transport::protobuf::Header& message) {
	return kTransportSuccess;
}

int Rudp::GetSocket() {
	return kTransportSuccess;
}

}  // namespace transport

}  //namespace lego