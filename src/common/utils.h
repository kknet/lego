#pragma once

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <string>
#include <chrono>

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
            DEBUG("%s:[handled: %d] [hash: %llu][hop: %d][src_net: %u][des_net: %u][id:%u]" \
                "[broad: %d][universal: %d][type: %d] %s", \
                std::string(pre).c_str(), \
                message.handled(), \
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
    kBlockMessage = 7,
    kRelayMessage = 8,  // any not handle message will routing by root

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
std::string CreateGID(const std::string& pubkey);
inline static std::string GetTxDbKey(bool from, const std::string& gid) {
    if (from) {
        return std::string("TX_from_") + gid;
    } else {
        return std::string("TX_to_") + gid;
    }
}

inline static std::string GetHeightDbKey(
        uint32_t netid,
        uint32_t pool_index,
        uint64_t height) {
    return std::string("H_" + std::to_string(netid) + "_" +
            std::to_string(pool_index) + "+" + std::to_string(height));
}

inline static std::string TimestampToDatetime(time_t timestamp) {
    struct tm* p = localtime(&timestamp);
    char time_str[64];
    memset(time_str, 0, sizeof(time_str));
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", p);
    return time_str;
}

inline static std::string MicTimestampToDatetime(int64_t timestamp) {
    int64_t milli = timestamp + (int64_t)(8 * 60 * 60 * 1000);
    auto mTime = std::chrono::milliseconds(milli);
    auto tp = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>(mTime);
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm* now = std::gmtime(&tt);
    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%4d%02d%02d %02d:%02d:%02d",
            now->tm_year + 1900,
            now->tm_mon + 1,
            now->tm_mday,
            now->tm_hour,
            now->tm_min,
            now->tm_sec);
    return time_str;
}

uint64_t TimeStampMsec();
uint64_t TimeStampUsec();
uint32_t RandomCountry();

void itimeofday(long *sec, long *usec);
int64_t iclock64(void);
uint32_t iclock();
void SignalRegister();

}  // namespace common

}  // namespace lego
