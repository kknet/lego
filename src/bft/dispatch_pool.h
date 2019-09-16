#pragma once

#include "bft/basic_bft/transaction/tx_pool_manager.h"
#include "bft/bft_interface.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"

namespace lego {

namespace bft {

class DispatchPool {
public:
    static DispatchPool* Instance();
    int Dispatch(
            const transport::protobuf::Header& header,
            const bft::protobuf::BftMessage& bft_msg);
    int Dispatch(const protobuf::TxInfo& tx_info);

    void GetTx(uint32_t& pool_index, std::vector<TxItemPtr>& res_vec);
    bool HasTx(const std::string& acc_addr, bool to, const std::string& gid);
    bool HasTx(uint32_t pool_index, bool to, const std::string& gid);
    TxItemPtr GetTx(uint32_t pool_index, bool to, const std::string& gid);
    void BftOver(BftInterfacePtr& bft_ptr);
    bool TxLockPool(uint32_t pool_index);

private:
    DispatchPool();
    ~DispatchPool();

    int AddTx(const bft::protobuf::BftMessage& bft_msg);

    TxPoolManager tx_pool_;

    DISALLOW_COPY_AND_ASSIGN(DispatchPool);
};

}  // namespace bft

}  // namespace lego
