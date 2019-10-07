#pragma once

#include "common/utils.h"
#include "dht/node.h"
#include "transport/proto/transport.pb.h"
#include "bft/basic_bft/transaction/tx_pool.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"
#include "bft/proto/bft.pb.h"

namespace lego {

namespace bft {

class TxProto {
public:
    static void SetDefaultBroadcastParam(
            transport::protobuf::BroadcastParam* broad_param);
    static void CreateTxRequest(
            const dht::NodePtr& local_node,
            const std::string& gid,
            uint64_t rand_num,
            transport::protobuf::Header& msg);
    static void CreateTxBlock(
            uint32_t pool_idx,
            const std::vector<TxItemPtr>& tx_vec,
            bft::protobuf::LeaderTxPrepare& bft_msg);

private:
    DISALLOW_COPY_AND_ASSIGN(TxProto);
};

}  // namespace bft

}  // namespace lego
