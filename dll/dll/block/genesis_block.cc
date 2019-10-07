#include "stdafx.h"
#include "block/genesis_block.h"

#include "common/hash.h"
#include "common/encode.h"
#include "db/db.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"

namespace lego {

namespace block {

int GenesisBlock::WriteGenesisBlock(uint32_t pool_idx, std::string& sha256) {
    bft::protobuf::Block block_item;
    block_item.set_height(0);
    auto tx_block = block_item.mutable_tx_block();
    tx_block->set_prehash("");
    tx_block->set_version(0);
    tx_block->set_elect_ver(0);
    tx_block->set_rc_hash("");
    tx_block->set_agg_sign("");
    tx_block->set_agg_pubkey("");
    tx_block->set_tx_id(0);
    tx_block->set_tx_hash("");
    tx_block->set_tx_root_hash("");
    tx_block->set_network_id(0);
    auto tx_list = tx_block->mutable_tx_list();
    static const std::vector<uint32_t> kNumVec{
        53, 48, 4, 124, 36, 6, 144, 35, 69, 138, 148, 110, 42, 112, 215, 31, 16, 146,
        12, 108, 21, 57, 9, 65, 22, 120, 140, 2, 130, 17, 135, 32, 5, 64, 54, 79, 25,
        13, 119, 8, 345, 88, 29, 166, 3, 11, 167, 94, 52, 33, 60, 23, 55, 46, 63, 15,
        156, 1, 123, 70, 239, 96, 20, 27
    };

    auto tx = tx_list->Add();
    tx->set_version(0);
    tx->set_gid("genesis_gid");
    tx->set_from(std::to_string(kNumVec[pool_idx]));
    assert(common::GetPoolIndex(tx->from()) == pool_idx);
    tx->set_from_pubkey("");
    tx->set_from_sign("");
    tx->set_to("");
    tx->set_amount(0);
    tx->set_gas_limit(0);
    tx->set_gas_price(0);
    tx->set_gas_used(0);
    tx->set_balance(0);
    tx->set_to_add(false);
    sha256 = common::Hash::Hash256(tx_block->SerializeAsString());
    block_item.set_hash(sha256);
    auto st = db::Db::Instance()->Put(sha256, block_item.SerializeAsString());
    if (!st.ok()) {
        BLOCK_ERROR("write genesis block failed!");
        assert(false);
        return kBlockError;
    }
    BLOCK_INFO("create genesis block success[%s]",
            common::Encode::HexEncode(sha256).c_str());
    return kBlockSuccess;
}

}  // namespace block

}  // namespace lego
