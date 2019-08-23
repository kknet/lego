#pragma once

#include <functional>
#include <string>

#include "transport/transport_utils.h"

namespace lego {

namespace transport {

struct Endpoint {
	Endpoint(const std::string& in_ip, uint16_t in_port) : ip(in_ip), port(in_port) {}
	std::string ip;
	uint16_t port;
    bool operator==(const Endpoint& other)const {
        return ip == other.ip && port == other.port;
    }
};

}  // namespace transport

}  // namespace lego


namespace std {
	template <>
	struct hash<lego::transport::Endpoint> {
		size_t operator()(lego::transport::Endpoint const& endpoint) const {
			size_t const h1(std::hash<std::string>{}(endpoint.ip));
			size_t const h2(std::hash<uint16_t>{}(endpoint.port));
			return h1 ^ (h2 << 1);
		}
	};
}

