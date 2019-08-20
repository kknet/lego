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

uint64_t TimeStampMsec();
uint64_t TimeStampUsec();
uint32_t RandomCountry();

static inline void itimeofday(long *sec, long *usec) {
#if defined(__unix)
	struct timeval time;
	gettimeofday(&time, NULL);
	if (sec) *sec = time.tv_sec;
	if (usec) *usec = time.tv_usec;
#else
	static long mode = 0, addsec = 0;
	BOOL retval;
	static IINT64 freq = 1;
	IINT64 qpc;
	if (mode == 0) {
		retval = QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
		freq = (freq == 0) ? 1 : freq;
		retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
		addsec = (long)time(NULL);
		addsec = addsec - (long)((qpc / freq) & 0x7fffffff);
		mode = 1;
	}
	retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
	retval = retval * 2;
	if (sec) *sec = (long)(qpc / freq) + addsec;
	if (usec) *usec = (long)((qpc % freq) * 1000000 / freq);
#endif
}

static inline int64_t iclock64(void) {
	long s, u;
	IINT64 value;
	itimeofday(&s, &u);
	value = ((IINT64)s) * 1000 + (u / 1000);
	return value;
}

static inline uint32_t iclock() {
	return static_cast<uint32_t>(iclock64() & 0xfffffffful);
}

}  // namespace common

}  // namespace lego
