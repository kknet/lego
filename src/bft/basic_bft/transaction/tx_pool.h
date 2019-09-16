#pragma once

#include <memory>
#include <map>
#include <atomic>
#include <chrono>
#include <mutex>
#include <unordered_set>
#include <vector>
#include <set>

#include "common/utils.h"
#include "common/hash.h"
#include "common/global_info.h"
#include "bft/bft_utils.h"
#include "bft/bft_interface.h"
#include "network/network_utils.h"

namespace lego {

namespace bft {

struct TxItem {
    TxItem(
            const std::string& in_gid,
            const std::string& in_from_acc_addr,
            const std::string& in_from_pubkey,
            const std::string& in_from_sign,
            const std::string& in_to_acc_addr,
            uint64_t in_lego_count)
            : gid(in_gid),
              from_acc_addr(in_from_acc_addr),
              from_pubkey(in_from_pubkey),
              from_sign(in_from_sign),
              to_acc_addr(in_to_acc_addr),
              lego_count(in_lego_count) {
        delta_time = (std::chrono::steady_clock::now() +
                std::chrono::microseconds(kBftStartDeltaTime));
        time_valid += common::TimeStampUsec() + kBftStartDeltaTime;
		if (in_to_acc_addr.empty()) {
			// may be use shard load info
			create_acc_network_id = network::GetConsensusShardNetworkId(in_from_acc_addr);
		}
    }

    void add_attr(const std::string& key, const std::string& val) {
        attr_map[key] = val;
    }
    std::string gid;
    std::string from_acc_addr;
    std::string from_pubkey;
    std::string from_sign;
    std::string to_acc_addr;
    uint64_t lego_count{ 0 };
    bool add_to_acc_addr{ false };
    // delay to wait all node ready
    std::chrono::steady_clock::time_point delta_time;
    uint64_t time_valid{ 0 };
    uint64_t index;
	uint32_t create_acc_network_id{ 0 };
    std::map<std::string, std::string> attr_map;
};

typedef std::shared_ptr<TxItem> TxItemPtr;

class TxPool {
public:
    TxPool();
    ~TxPool();

    int AddTx(TxItemPtr& account_ptr);
    void GetTx(std::vector<TxItemPtr>& res_vec);
    bool TxPoolEmpty();
    bool HasTx(bool to, const std::string& tx_gid);
    TxItemPtr GetTx(bool to, const std::string& tx_gid);
    void BftOver(BftInterfacePtr& bft_ptr);
    void set_pool_index(uint32_t pool_idx) {
        pool_index_ = pool_idx;
    }

private:
    static std::atomic<uint64_t> pool_index_gen_;

    std::map<uint64_t, TxItemPtr> tx_pool_;
    std::unordered_map<std::string, uint64_t> added_tx_map_;
    std::mutex tx_pool_mutex_;
    uint32_t pool_index_;

    DISALLOW_COPY_AND_ASSIGN(TxPool);
};

}  // namespace bft

}  // namespace lego
