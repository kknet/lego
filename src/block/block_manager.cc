#include "block/block_manager.h"

#include "common/encode.h"
#include "db/db.h"
#include "network/route.h"
#include "block/block_utils.h"
#include "block/account_manager.h"
#include "block/genesis_block.h"

namespace lego {

namespace block {

BlockManager* BlockManager::Instance() {
    static BlockManager ins;
    return &ins;
}
BlockManager::BlockManager() {
    network::Route::Instance()->RegisterMessage(
            common::kBlockMessage,
            std::bind(&BlockManager::HandleMessage, this, std::placeholders::_1));
}

BlockManager::~BlockManager() {}

int BlockManager::Init(common::Config& conf) {
    bool genesis = false;
    conf.Get("lego", "genesis", genesis);
    if (genesis) {
        for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
            std::string genesis_hash;
            if (GenesisBlock::WriteGenesisBlock(i, genesis_hash) != kBlockSuccess) {
                BLOCK_ERROR("genesis write block failed!");
                return kBlockError;
            }

            if (LoadAllTx(genesis_hash) != kBlockSuccess) {
                BLOCK_ERROR("load tx from db failed!");
                return kBlockError;
            }
        }
        std::cout << "init block manager success." << std::endl;
        return kBlockSuccess;
    }

    // check network_id is consensus shard
    if (LoadTxBlocks(conf) != kBlockSuccess) {
        return kBlockError;
    }
    return kBlockSuccess;
}

void BlockManager::HandleMessage(transport::protobuf::Header& header) {

}

int BlockManager::LoadTxBlocks(const common::Config& conf) {
    uint32_t network_id;
    if (!conf.Get("tx_block", "network_id", network_id)) {
        BLOCK_ERROR("get tx_block network_id from config failed!");
        return kBlockError;
    }

    for (uint32_t i = 0; i < common::kImmutablePoolSize; ++i) {
        std::string key = GetLastBlockHash(common::kTestForNetworkId, i);
        std::string last_block_hash;
        auto st = db::Db::Instance()->Get(key, &last_block_hash);
        if (!st.ok()) {
            BLOCK_ERROR("get last block [%d][%d] error.", common::kTestForNetworkId, i);
            return kBlockError;
        }

        if (LoadAllTx(last_block_hash) != kBlockSuccess) {
            BLOCK_ERROR("load tx from db failed!");
            return kBlockError;
        }
    }
    return kBlockSuccess;
}

int BlockManager::LoadAllTx(const std::string& frist_hash) {
    std::string tmp_str = frist_hash;
    while (true) {
        std::string block_str;
        auto st = db::Db::Instance()->Get(tmp_str, &block_str);
        if (!st.ok()) {
            BLOCK_ERROR("load block from db failed[%s]",
                common::Encode::HexEncode(tmp_str).c_str());
            // call sync module
            return kBlockDbNotExists;
        }

        bft::protobuf::Block block_item;
        if (!block_item.ParseFromString(block_str) || !block_item.has_tx_block()) {
            BLOCK_ERROR("protobuf::Block ParseFromString failed!");
            return kBlockDbDataInvalid;
        }

        AccountManager::Instance()->AddBlockItem(block_item);
        tmp_str = block_item.tx_block().prehash();
        if (tmp_str.empty()) {
            break;
        }
    }
    return kBlockSuccess;
}

int BlockManager::AddNewBlock(const bft::protobuf::Block& block_item) {
    auto st = db::Db::Instance()->Put(block_item.hash(), block_item.SerializeAsString());
    if (!st.ok()) {
        return kBlockError;
    }
    AccountManager::Instance()->AddBlockItem(block_item);
    return kBlockSuccess;
}

}  // namespace block

}  // namespace lego