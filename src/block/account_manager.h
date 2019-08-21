#pragma once

#include <unordered_map>

#include "common/config.h"
#include "block/block_utils.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"

namespace lego {

namespace block {

struct AccountInfo {
    AccountInfo(const std::string& acc, int64_t b, uint64_t h)
            : account_id(acc), balance(b), height(h) {}
    std::string account_id;
    int64_t balance;
    uint64_t height;
    std::atomic<uint32_t> out_count{ 0 };
    std::atomic<uint32_t> in_count{ 0 };
    std::atomic<uint64_t> out_lego{ 0 };
    std::atomic<uint64_t> in_lego{ 0 };
    uint32_t new_height{ 0 };
};
typedef std::shared_ptr<AccountInfo> AccountInfoPtr;

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
