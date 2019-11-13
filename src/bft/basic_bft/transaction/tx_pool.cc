#include "bft/basic_bft/transaction/tx_pool.h"

#include <cassert>

#include "bft/bft_utils.h"
#include "common/encode.h"

namespace lego {

namespace bft {

std::atomic<uint64_t> TxPool::pool_index_gen_{ 0 };

TxPool::TxPool() {}

TxPool::~TxPool() {}

int TxPool::AddTx(TxItemPtr& tx_ptr) {
    assert(tx_ptr != nullptr);
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    std::string uni_gid = tx_ptr->gid;
    if (tx_ptr->add_to_acc_addr) {
        uni_gid = std::string("t_") + tx_ptr->gid;
    }
    auto iter = added_tx_map_.find(uni_gid);
    if (iter != added_tx_map_.end()) {
        BFT_ERROR("tx gid[%d][%s] has added!",
                tx_ptr->add_to_acc_addr,
                common::Encode::HexEncode(uni_gid).c_str());
        return kBftTxAdded;
    }

    BFT_ERROR("tx gid[%d][%s] now added!",
            tx_ptr->add_to_acc_addr,
            common::Encode::HexEncode(uni_gid).c_str());
    uint64_t tx_index = pool_index_gen_.fetch_add(1);
    added_tx_map_.insert(std::make_pair(uni_gid, tx_index));
    tx_pool_[tx_index] = tx_ptr;
    tx_ptr->index = tx_index;
    return kBftSuccess;
}

void TxPool::GetTx(std::vector<TxItemPtr>& res_vec) {
    auto timestamp_now = common::TimeStampUsec();
    {
        std::lock_guard<std::mutex> guard(tx_pool_mutex_);
        for (auto iter = tx_pool_.begin(); iter != tx_pool_.end(); ++iter) {
            if (iter->second == nullptr) {
//                 assert(false);
                continue;
            }

            if (iter->second->time_valid <= timestamp_now) {
                res_vec.push_back(iter->second);
                if (res_vec.size() >= kBftOneConsensusMaxCount) {
                    break;
                }
            }
        }
    }

    if (res_vec.size() < kBftOneConsensusMinCount) {
        res_vec.clear();
    }
}

bool TxPool::HasTx(bool to, const std::string& tx_gid) {
    std::string uni_gid = tx_gid;
    if (to) {
        uni_gid = std::string("t_") + tx_gid;
    }
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    auto iter = added_tx_map_.find(uni_gid);
    return iter != added_tx_map_.end();
}

TxItemPtr TxPool::GetTx(bool to, const std::string& tx_gid) {
    std::string uni_gid = tx_gid;
    if (to) {
        uni_gid = std::string("t_") + tx_gid;
    }
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    auto iter = added_tx_map_.find(uni_gid);
    if (iter == added_tx_map_.end()) {
        return nullptr;
    }

    auto item_iter = tx_pool_.find(iter->second);
    if (item_iter != tx_pool_.end()) {
        return item_iter->second;
    }
    return nullptr;
}

bool TxPool::TxPoolEmpty() {
    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    return tx_pool_.empty();
}

void TxPool::BftOver(BftInterfacePtr& bft_ptr) {
    if (bft_ptr->status() != kBftCommited) {
        return;
    }

    std::lock_guard<std::mutex> guard(tx_pool_mutex_);
    auto item_vec = bft_ptr->item_index_vec();
    for (uint32_t i = 0; i < item_vec.size(); ++i) {
        auto iter = tx_pool_.find(item_vec[i]);
        if (iter != tx_pool_.end()) {
//             auto set_iter = added_tx_map_.find(iter->second->gid);
//             if (set_iter != added_tx_map_.end()) {
//                 added_tx_map_.erase(set_iter);
//             }
            tx_pool_.erase(iter);
        }
    }
}

}  // namespace bft

}  // namespace lego
