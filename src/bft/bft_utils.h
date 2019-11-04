#pragma once

#include <limits>

#include "common/utils.h"
#include "common/log.h"
#include "common/hash.h"

#define BFT_DEBUG(fmt, ...) DEBUG("[bft]" fmt, ## __VA_ARGS__)
#define BFT_INFO(fmt, ...) INFO("[bft]" fmt, ## __VA_ARGS__)
#define BFT_WARN(fmt, ...) WARN("[bft]" fmt, ## __VA_ARGS__)
#define BFT_ERROR(fmt, ...) ERROR("[bft]" fmt, ## __VA_ARGS__)

#ifdef LEGO_TRACE_BFT
#define LEGO_BFT_DEBUG_FOR_CONSENSUS(pre, bft_ptr) \
    do { \
        BFT_DEBUG("[CONSENSUS]%s: [gid: %s][status: %d(%s)][item_cnt: %d]" \
                "[pool_index: %d][network_id: %d]" \
                "[rand_num: %llu][l_pc_agree: %d][l_c_aggree: %d]" \
                "[member_count: %d][min_cnt: %d]", \
                std::string(pre).c_str(), \
                common::Encode::HexEncode(bft_ptr->gid()).c_str(), \
                bft_ptr->status(), \
                StatusToString(bft_ptr->status()).c_str(), \
                bft_ptr->bft_item_count(), \
                bft_ptr->pool_index(), \
                bft_ptr->network_id(), \
                bft_ptr->rand_num(), \
                bft_ptr->leader_precommit_agree(), \
                bft_ptr->leader_commit_agree(), \
                bft_ptr->member_count(), \
                bft_ptr->min_agree_member_count()); \
    } while (0)

#define LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE(pre, bft_ptr, message) \
    do { \
        BFT_DEBUG("[CONSENSUS]%s: [hash: %llu][id: %u][hop: %d][broad: %d]" \
                "[gid: %s][status: %d(%s)][item_cnt: %d]" \
                "[pool_index: %d][network_id: %d]" \
                "[rand_num: %llu][l_pc_agree: %d][l_c_aggree: %d]" \
                "[member_count: %d][min_cnt: %d]", \
                std::string(pre).c_str(), \
                message.hash(), \
                message.id(), \
                message.hop_count(), \
                message.has_broadcast(), \
                common::Encode::HexEncode(bft_ptr->gid()).c_str(), \
                bft_ptr->status(), \
                StatusToString(bft_ptr->status()).c_str(), \
                bft_ptr->bft_item_count(), \
                bft_ptr->pool_index(), \
                bft_ptr->network_id(), \
                bft_ptr->rand_num(), \
                bft_ptr->leader_precommit_agree(), \
                bft_ptr->leader_commit_agree(), \
                bft_ptr->member_count(), \
                bft_ptr->min_agree_member_count()); \
    } while (0)

#else
#define LEGO_BFT_DEBUG_FOR_CONSENSUS(pre, bft_ptr)
#define LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE(pre, bft_ptr, message)
#endif

namespace lego {

namespace bft {

enum BftErrorCode {
    kBftSuccess = 0,
    kBftError = 1,
    kBftAdded = 2,
    kBftNotExists = 4,
    kBftTxAdded = 5,
    kBftNoNewAccount = 6,
    kBftInvalidPackage = 7,
    kBftTxNotExists = 8,
    kBftAccountNotExists = 9,
    kBftAccountBalanceError = 10,
    kBftAccountExists = 11,
    kBftBlockHashError = 12,
    kBftBlockHeightError = 13,
    kBftPoolIndexError = 14,
    kBftBlockNotExists = 15,
    kBftBlockPreHashError = 16,
    kBftNetwokInvalid = 17,
    kBftLeaderInfoInvalid = 18,
};

enum BftStatus {
    kBftInit = 0,
    kBftPrepare = 1,
    kBftPreCommit = 2,
    kBftCommit = 3,
    kBftCommited = 4,
    kBftToTxInit = 5,
};

enum BftRole {
    kBftRootCongress = 0,
    kBftShard = 1,
};

enum BftLeaderCheckStatus {
    kBftWaitingBackup = 0,
    kBftOppose = 1,
    kBftAgree = 2,
    kBftHandled = 3,
    kBftReChallenge = 4,
};

static const uint32_t kBftOneConsensusMaxCount = 32u;  // every consensus
static const uint32_t kBftOneConsensusMinCount = 1u;
// bft will delay 500ms for all node ready
static const uint32_t kBftStartDeltaTime = 500u * 1000u;

// broadcast default param
static const uint32_t kBftBroadcastIgnBloomfilterHop = 1u;
static const uint32_t kBftBroadcastStopTimes = 2u;
static const uint32_t kBftHopLimit = 5u;
static const uint32_t kBftHopToLayer = 2u;
static const uint32_t kBftNeighborCount = 7u;
static const uint32_t kBftLeaderBitmapSize = 640u;
static const uint32_t kBftTimeout = 6u * 1000u * 1000u;  // bft timeout 6s
static const uint32_t kBftTimeoutCheckPeriod = 10u * 1000u * 1000u;
static const uint32_t kBftLeaderPrepareWaitPeriod = 3u * 1000u * 1000u;
static const uint32_t kInvalidMemberIndex = (std::numeric_limits<uint32_t>::max)();

static const std::string kTransactionPbftAddress("Transaction");
static const std::string kVpnSubscriptionDeduction("vpn_subscription_deduction");

inline static std::string StatusToString(uint32_t status) {
    switch (status) {
    case kBftInit:
        return "bft_init";
    case kBftPrepare:
        return "bft_prepare";
    case kBftPreCommit:
        return "bft_precommit";
    case kBftCommit:
        return "bft_commit";
    case kBftCommited:
        return "bft_success";
    default:
        return "unknown";
    }
}

}  // namespace bft

}  //namespace lego
