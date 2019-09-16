#include "bft/dispatch_pool.h"

#include "bft/bft_utils.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"

namespace lego {

namespace bft {

DispatchPool::DispatchPool() {}

DispatchPool::~DispatchPool() {}

DispatchPool* DispatchPool::Instance() {
    static DispatchPool ins;
    return &ins;
}

int DispatchPool::Dispatch(
        const transport::protobuf::Header& header,
        const bft::protobuf::BftMessage& bft_msg) {
    assert(bft_msg.has_bft_address());
    if (bft_msg.bft_address() == kTransactionPbftAddress) {
        return AddTx(bft_msg);
    }
    assert(false);
    return kBftSuccess;
}

int DispatchPool::Dispatch(const protobuf::TxInfo& tx_info) {
    auto tx_ptr = std::make_shared<TxItem>(
        tx_info.gid(),
        tx_info.from(),
        tx_info.from_pubkey(),
        tx_info.from_sign(),
        tx_info.to(),
        tx_info.amount(),
        tx_info.type());
    tx_ptr->add_to_acc_addr = tx_info.to_add();
    return tx_pool_.AddTx(tx_ptr);
}

int DispatchPool::AddTx(const bft::protobuf::BftMessage& bft_msg) {
    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("protobuf::TxBft ParseFromString failed!");
        return kBftError;
    }
    // check sign for gid
    assert(tx_bft.has_new_tx());
    auto tx_ptr = std::make_shared<TxItem>(
            tx_bft.new_tx().gid(),
            tx_bft.new_tx().from_acc_addr(),
            tx_bft.new_tx().from_pubkey(),
            tx_bft.new_tx().from_sign(),
            tx_bft.new_tx().to_acc_addr(),
            tx_bft.new_tx().lego_count(),
            tx_bft.new_tx().type());
    return tx_pool_.AddTx(tx_ptr);
}

 void DispatchPool::GetTx(uint32_t& pool_index, std::vector<TxItemPtr>& res_vec) {
    return tx_pool_.GetTx(pool_index, res_vec);
}

bool DispatchPool::HasTx(const std::string& acc_addr, bool to, const std::string& gid) {
    return tx_pool_.HasTx(acc_addr, to, gid);
}

bool DispatchPool::HasTx(uint32_t pool_index, bool to, const std::string& gid) {
    return tx_pool_.HasTx(pool_index, to, gid);
}

TxItemPtr DispatchPool::GetTx(uint32_t pool_index, bool to, const std::string& gid) {
    return tx_pool_.GetTx(pool_index, to, gid);
}

void DispatchPool::BftOver(BftInterfacePtr& bft_ptr) {
    if (bft_ptr->name() == kTransactionPbftAddress) {
        tx_pool_.BftOver(bft_ptr);
    }
}

bool DispatchPool::TxLockPool(uint32_t pool_index) {
    return tx_pool_.LockPool(pool_index);
}

}  // namespace bft

}  // namespace lego
