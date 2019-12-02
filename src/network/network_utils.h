#pragma once

#include "common/utils.h"
#include "common/log.h"
#include "common/hash.h"
#include "common/global_info.h"

#define NETWORK_DEBUG(fmt, ...) DEBUG("[network]" fmt, ## __VA_ARGS__)
#define NETWORK_INFO(fmt, ...) INFO("[network]" fmt, ## __VA_ARGS__)
#define NETWORK_WARN(fmt, ...) WARN("[network]" fmt, ## __VA_ARGS__)
#define NETWORK_ERROR(fmt, ...) ERROR("[network]" fmt, ## __VA_ARGS__)

namespace lego {

namespace network {

enum NetworkErrorCode {
    kNetworkSuccess = 0,
    kNetworkError = 1,
    kNetworkJoinUniversalError = 2,
    kNetworkJoinShardFailed = 3,
    kNetworkNoBootstrapNodes = 4,
    kNetworkNetworkJoined = 5,
    kNetworkNetworkNotJoined = 6,
};

// consensus shard 3 - 4097
// service shard 4098 - 10240
// universal 0
// node network 1
// root congress 2
static const uint32_t kNetworkMaxDhtCount = 10240u;
static const uint32_t kUniversalNetworkId = 0u;  // all network join(for find network)
static const uint32_t kNodeNetworkId = 1u;  // just node id join(for broadcast)
static const uint32_t kRootCongressNetworkId = 2u;
static const uint32_t kConsensusShardBeginNetworkId = 3u;  // eq
static const uint32_t kConsensusShardEndNetworkId = 4099u;  // less
static const uint32_t kConsensusShardNetworkCount = (
        kConsensusShardEndNetworkId - kConsensusShardBeginNetworkId + 1);
static const uint32_t kServiceShardBeginNetworkId = kConsensusShardEndNetworkId;  // eq
static const uint32_t kServiceShardEndNetworkId = kNetworkMaxDhtCount;  // less

enum ServiceNetworkType {
    kVpnNetworkId = kServiceShardBeginNetworkId,
    kVpnRouteNetworkId,
    kConsensusSubscription,
};

inline static uint32_t GetConsensusShardNetworkId(const std::string& account_address) {
	return 4;
    return (kConsensusShardBeginNetworkId + (
            common::Hash::Hash32(account_address) %
			common::GlobalInfo::Instance()->consensus_shard_count()));
}

inline static std::string GetAccountAddressByPublicKey(const std::string& pub_key) {
    return common::Hash::Sha256(pub_key);
}

}  // namespace network

}  // namespace lego
