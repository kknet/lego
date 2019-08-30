#pragma once

#include <unordered_map>
#include <queue>

#include "common/config.h"
#include "block/block_utils.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"

namespace lego {

namespace block {

struct TxBlockInfo {
    TxBlockInfo(
            const std::string& h,
            uint64_t heih,
            uint32_t pre_net,
            uint32_t now_net,
            uint32_t pidx)
            : hash(h),
              height(heih),
              pre_network_id(pre_net),
              now_network_id(now_net),
              pool_index(pidx) {}
    std::string hash;
    uint64_t height;
    uint32_t pre_network_id;
    uint32_t now_network_id;
    uint32_t pool_index;
};
typedef std::shared_ptr<TxBlockInfo> TxBlockInfoPtr;

class AccountManager {
public:
    static AccountManager* Instance();
    int AddBlockItem(const bft::protobuf::Block& block_item);
    AccountInfoPtr GetAcountInfo(const std::string& acc_id);
    TxBlockInfoPtr GetBlockInfo(uint32_t pool_idx);
    uint32_t addr_count() {
        std::lock_guard<std::mutex> gaurd(acc_map_mutex_);
        return acc_map_.size();
    }

    uint64_t all_acc_lego() {
        uint64_t all_lego = 0;
        std::lock_guard<std::mutex> gaurd(acc_map_mutex_);
        for (auto iter = acc_map_.begin(); iter != acc_map_.end(); ++iter) {
            all_lego += iter->second->balance;
        }
        return all_lego;
    }

    std::shared_ptr<std::unordered_map<std::string, AccountInfoPtr>> acc_map_ptr() {
        std::lock_guard<std::mutex> gaurd(acc_map_mutex_);
        return std::make_shared<std::unordered_map<std::string, AccountInfoPtr>>(acc_map_);
    }

private:
    AccountManager();
    ~AccountManager();

    int CheckNetworkIdValid(const std::string& acc_addr);
    void AddAccount(const AccountInfoPtr& acc_ptr);
    void SetPool(const TxBlockInfoPtr& block_ptr);

    std::unordered_map<std::string, AccountInfoPtr> acc_map_;
    std::mutex acc_map_mutex_;
    TxBlockInfoPtr* network_block_{ nullptr };
    std::mutex network_block_mutex_;

    DISALLOW_COPY_AND_ASSIGN(AccountManager);
};

}  // namespace block

}  //namespace lego
