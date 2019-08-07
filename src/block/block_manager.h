#pragma once

#include "common/config.h"
#include "transport/proto/transport.pb.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"
#include "block/block_utils.h"
#include "block/proto/block.pb.h"

namespace lego {

namespace block {

class BlockManager {
public:
    static BlockManager* Instance();
    int Init(common::Config& conf);
    int AddNewBlock(const bft::protobuf::Block& block_item);

private:
    BlockManager();
    ~BlockManager();
    void HandleMessage(transport::protobuf::Header& header);
    int LoadTxBlocks(const common::Config& conf);
    int LoadAllTx(const std::string& frist_hash);
    int HandleGetBlockRequest(
            transport::protobuf::Header& header,
            protobuf::BlockMessage& block_msg);

    DISALLOW_COPY_AND_ASSIGN(BlockManager);
};

}  // namespace block

}  // namespace lego
