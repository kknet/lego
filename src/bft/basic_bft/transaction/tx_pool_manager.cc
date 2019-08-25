#include "bft/basic_bft/transaction/tx_pool_manager.h"

#include "common/hash.h"
#include "common/string_utils.h"
#include "common/global_info.h"
#include "block/account_manager.h"
#include "network/network_utils.h"

namespace lego {

namespace bft {

TxPoolManager::TxPoolManager() {
    tx_pool_ = new TxPool[common::kImmutablePoolSize];
    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        tx_pool_[i].set_pool_index(i);
    }
}

TxPoolManager::~TxPoolManager() {
    if (tx_pool_ != nullptr) {
        delete []tx_pool_;
    }
}

int TxPoolManager::AddTx(TxItemPtr& tx_ptr) {
    if (!TxValid(tx_ptr)) {
//         BFT_ERROR("tx invalid.");
        return kBftError;
    }

    uint32_t pool_index = common::kInvalidPoolIndex;
    if (!tx_ptr->add_to_acc_addr) {
        pool_index = common::Hash::Hash32(tx_ptr->from_acc_addr);
    } else {
        pool_index = common::Hash::Hash32(tx_ptr->to_acc_addr);
    }
    
    pool_index %= common::kImmutablePoolSize;
    return tx_pool_[pool_index].AddTx(tx_ptr);
}

bool TxPoolManager::TxValid(TxItemPtr& tx_ptr) {
    std::string account_addr = network::GetAccountAddressByPublicKey(tx_ptr->from_pubkey);
    if (account_addr != tx_ptr->from_acc_addr) {
        BFT_ERROR("from accaddr not equal to from pub create addr.");
        return false;
    }

    if (tx_ptr->to_acc_addr.empty()) {
//         if (tx_ptr->lego_count != 0) {
//             return false;
//         }
// 
// 		if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
// 			BFT_ERROR("create account address must root conngress.not[%u]",
// 					common::GlobalInfo::Instance()->network_id());
// 			return false;
// 		}

        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(account_addr);
        if (acc_info != nullptr) {
//             BFT_ERROR("tx invalid. account address exists");
            return false;
        }
    } else {
        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(account_addr);
        if (acc_info == nullptr) {
            BFT_ERROR("tx invalid. account address not exists");
            return false;
        }

        if (acc_info->balance < static_cast<int64_t>(tx_ptr->lego_count)) {
            BFT_ERROR("tx invalid. balance error[%ll][%llu]",
					acc_info->balance,
					tx_ptr->lego_count);
            return false;
        }
    }
    return true;
}

void TxPoolManager::GetTx(uint32_t& pool_index, std::vector<TxItemPtr>& res_vec) {
    int valid_pool = -1;
    uint32_t pool_size = waiting_pools_.data().size() * 64;
    uint32_t rand_pos = rand() % pool_size;
    for (uint32_t i = rand_pos; i < pool_size; ++i) {
        if (!waiting_pools_.Valid(i) && !tx_pool_[i].TxPoolEmpty()) {
            std::lock_guard<std::mutex> guard(waiting_pools_mutex_);
            if (!waiting_pools_.Valid(i) && !tx_pool_[i].TxPoolEmpty()) {
                waiting_pools_.Set(i);
                valid_pool = i;
                break;
            }
        }
    }

    if (valid_pool < 0) {
        for (uint32_t i = 0; i < rand_pos; ++i) {
            if (!waiting_pools_.Valid(i) && !tx_pool_[i].TxPoolEmpty()) {
                std::lock_guard<std::mutex> guard(waiting_pools_mutex_);
                if (!waiting_pools_.Valid(i) && !tx_pool_[i].TxPoolEmpty()) {
                    waiting_pools_.Set(i);
                    valid_pool = i;
                    break;
                }
            }
        }

        if (valid_pool < 0) {
            return;
        }
    }
    pool_index = valid_pool;
    tx_pool_[valid_pool].GetTx(res_vec);
    if (res_vec.empty()) {
        std::lock_guard<std::mutex> guard(waiting_pools_mutex_);
        waiting_pools_.UnSet(valid_pool);
    }
}

bool TxPoolManager::HasTx(const std::string& acc_addr, bool to, const std::string& tx_gid) {
    uint32_t pool_index = common::GetPoolIndex(acc_addr);
    return tx_pool_[pool_index].HasTx(to, tx_gid);
}

bool TxPoolManager::HasTx(uint32_t pool_index, bool to, const std::string& tx_gid) {
    assert(pool_index < common::kImmutablePoolSize);
    return tx_pool_[pool_index].HasTx(to, tx_gid);
}

void TxPoolManager::BftOver(BftInterfacePtr& bft_ptr) {
    assert(bft_ptr->pool_index() < common::kImmutablePoolSize);
    tx_pool_[bft_ptr->pool_index()].BftOver(bft_ptr);
    std::lock_guard<std::mutex> guard(waiting_pools_mutex_);
    waiting_pools_.UnSet(bft_ptr->pool_index());
}

bool TxPoolManager::LockPool(uint32_t pool_index) {
    std::lock_guard<std::mutex> guard(waiting_pools_mutex_);
    if (waiting_pools_.Valid(pool_index)) {
        return false;
    }
    waiting_pools_.Set(pool_index);
    return true;
}

}  // namespace bft

}  // namespace bft
