#pragma once

#include "common/log.h"
#include "transport/proto/transport.pb.h"

#define TRANSPORT_DEBUG(fmt, ...) DEBUG("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_INFO(fmt, ...) INFO("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_WARN(fmt, ...) WARN("[transport]" fmt, ## __VA_ARGS__)
#define TRANSPORT_ERROR(fmt, ...) ERROR("[transport]" fmt, ## __VA_ARGS__)

namespace lego {

namespace transport {

enum TransportErrorCode {
    kTransportSuccess = 0,
    kTransportError = 1,
    kTransportTimeout = 2,
    kTransportClientSended = 3,
};

enum TransportPriority {
    kTransportPrioritySystem = 0,
    kTransportPriorityHighest = 1,
    kTransportPriorityHigh = 2,
    kTransportPriorityMiddle = 3,
    kTransportPriorityLow = 4,
    kTransportPriorityLowest = 5,
};

enum UdpPacketType {
	kOriginalUdp = 0,
	kKcpUdp = 1,
};

struct TransportHeader {
    uint32_t size;
    uint32_t type;
};

typedef std::function<void(protobuf::Header& message)> MessageProcessor;

static const uint32_t kMaxHops = 20u;
static const uint32_t kBroadcastMaxRelayTimes = 2u;
static const uint32_t kBroadcastMaxMessageCount = 1024u * 1024u;
static const uint32_t kUniqueMaxMessageCount = 1024u * 1024u;
static const uint32_t kKcpRecvWindowSize = 128u;
static const uint32_t kKcpSendWindowSize = 128u;

}  // namespace transport

}  // namespace lego
