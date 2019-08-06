#pragma once

#include <stdint.h>

#include <string>

#ifndef DISALLOW_COPY_AND_ASSIGN
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
        TypeName(const TypeName&); \
        TypeName& operator=(const TypeName&)
#endif  // !DISALLOW_COPY_AND_ASSIGN

#ifdef LEGO_TRACE_MESSAGE
struct Construct {
    uint32_t net_id;
    uint8_t country;
    uint8_t reserve1;
    uint8_t reserve2;
    uint8_t reserve3;
    char hash[24];
};

#define LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(pre, message) \
    do { \
        if (message.has_debug()) { \
            Construct* src_cons_key = (Construct*)(message.src_dht_key().c_str()); \
            Construct* des_cons_key = (Construct*)(message.des_dht_key().c_str()); \
            DEBUG("%s: [hash: %llu][hop: %d][src_net: %u][des_net: %u][id:%u]" \
                "[broad: %d][universal: %d][type: %d] %s", \
                std::string(pre).c_str(), \
                message.hash(), \
                message.hop_count(), \
                src_cons_key->net_id, \
                des_cons_key->net_id, \
                message.id(), \
                message.has_broadcast(), \
                message.universal(), \
                message.type(), \
                message.debug().c_str()); \
        } \
    } while (0)
#else
#define LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE(pre, message)
#endif

namespace lego {

namespace common {

enum MessageType {
    kDhtMessage = 0,
    kNatMessage = 1,
    kNetworkMessage = 2,
    kSyncMessage = 3,
    kBftMessage = 4,
    kElectMessage = 5,
    kServiceMessage = 6,

    kUdpDemoTestMessage,
    // max message type
    kLegoMaxMessageTypeCount,
};

enum CommonErrorCode {
    kCommonSuccess = 0,
    kCommonError = 1,
};

static const uint32_t kImmutablePoolSize = 64u;
static const uint32_t kInvalidPoolIndex = kImmutablePoolSize + 1;
static const uint32_t kTestForNetworkId = 4u;

uint32_t GetPoolIndex(const std::string& acc_addr);
std::string GetAccountAddress(const std::string& pubkey);

uint64_t TimeStampMsec();
uint64_t TimeStampUsec();

}  // namespace common

}  // namespace lego
