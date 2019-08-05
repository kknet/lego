#pragma once

#include <bitset>

#include "common/bitmap.h"
#include "bft/bft_utils.h"
#include "bft/basic_bft/transaction/tx_pool.h"
#include "bft/proto/bft_proto.h"
#include "bft/bft_interface.h"

namespace lego {

namespace bft {

class TxPoolManager {
public:
    TxPoolManager();
    ~TxPoolManager();
    int AddTx(TxItemPtr& tx_ptr);
    void GetTx(uint32_t& pool_index, std::vector<TxItemPtr>& res_vec);
    bool HasTx(const std::string& acc_addr, const std::string& tx_gid);
    bool HasTx(uint32_t pool_index, const std::string& tx_gid);
    void BftOver(BftInterfacePtr& bft_ptr);
    bool LockPool(uint32_t pool_index);
    bool TxValid(TxItemPtr& tx_ptr);

private:
    TxPool* tx_pool_{ nullptr };
    common::Bitmap waiting_pools_{ common::kImmutablePoolSize };
    std::mutex waiting_pools_mutex_;

    DISALLOW_COPY_AND_ASSIGN(TxPoolManager);
};

}  // namespace bft

}  // namespace bft
