#pragma once

#include <iostream>
#include <iomanip>
#include <functional>
#include <string>
#include <unordered_set>

#include "transport/transport_utils.h"

namespace lego {

namespace transport {

struct Endpoint {
	Endpoint(const std::string& in_ip, uint16_t in_port) : ip(in_ip), port(in_port) {}
	std::string ip;
	uint16_t port;
};

}  // namespace transport

}  // namespace lego

bool operator==(const lego::transport::Endpoint& lhs, const lego::transport::Endpoint& rhs) {
	return lhs.ip == rhs.ip && lhs.port == rhs.port;
}

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

