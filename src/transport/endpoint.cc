#include "stdafx.h"
#include "transport/endpoint.h"

namespace std {
    bool operator==(
        const lego::transport::Endpoint& lhs,
        const lego::transport::Endpoint& rhs) {
        return lhs.ip == rhs.ip && lhs.port == rhs.port;
    }
}
