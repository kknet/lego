#include "block/block_manager.h"

#include "common/encode.h"
#include "db/db.h"
#include "dht/dht_key.h"
#include "dht/base_dht.h"
#include "dht/node.h"
#include "network/route.h"
#include "network/universal_manager.h"
#include "network/network_utils.h"
#include "network/universal.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "block/block_utils.h"
#include "block/account_manager.h"
#include "block/genesis_block.h"
#include "block/proto/block.pb.h"
#include "block/proto/block_proto.h"

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

            if (LoadAllTx(genesis_hash, common::kTestForNetworkId, i) != kBlockSuccess) {
                BLOCK_ERROR("load tx from db failed!");
                return kBlockError;
            }
        }
        return kBlockSuccess;
    }

    // check network_id is consensus shard
    if (LoadTxBlocks(conf) != kBlockSuccess) {
        return kBlockError;
    }
    return kBlockSuccess;
}

void BlockManager::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() != common::kBlockMessage) {
        return;
    }

    protobuf::BlockMessage block_msg;
    if (!block_msg.ParseFromString(header.data())) {
        return;
    }

    if (block_msg.has_block_req()) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("block handle", header);
        HandleGetBlockRequest(header, block_msg);
    }

    if (block_msg.has_height_req()) {
        HandleGetHeightRequest(header, block_msg);
    }

    if (block_msg.has_acc_attr_req()) {
        HandleAttrGetRequest(header, block_msg);
    }

    if (block_msg.has_acc_attr_res()) {
        std::cout << "attr response coming." << std::endl;
    }
}

void BlockManager::HandleAttrGetRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    if (!block_msg.has_acc_attr_req()) {
        return;
    }

    auto account_ptr = block::AccountManager::Instance()->GetAcountInfo(
            block_msg.acc_attr_req().account());
    if (account_ptr == nullptr) {
        return;
    }

    uint64_t height = 0;
    {
        std::lock_guard<std::mutex> gurad(account_ptr->attrs_with_height_mutex);
        auto iter = account_ptr->attrs_with_height.find(block_msg.acc_attr_req().attr_key());
        if (iter != account_ptr->attrs_with_height.end()) {
            height = iter->second;
        }
    }

    if (height > block_msg.acc_attr_req().height()) {
        uint32_t netid = network::GetConsensusShardNetworkId(
                block_msg.acc_attr_req().account());
        uint32_t pool_idx = common::GetPoolIndex(block_msg.acc_attr_req().account());
        std::string height_db_key = common::GetHeightDbKey(
                netid,
                pool_idx,
                height);
        std::string block_hash;
        auto st = db::Db::Instance()->Get(height_db_key, &block_hash);
        if (!st.ok()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("get block hash error", header);
            return;
        }

        if (block_hash.empty()) {
            return;
        }

        std::string block_data;
        st = db::Db::Instance()->Get(block_hash, &block_data);
        if (!st.ok()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("get block data error", header);
            return;
        }

        protobuf::BlockMessage block_msg_res;
        auto attr_res = block_msg_res.mutable_acc_attr_res();
        attr_res->set_block(block_data);
        attr_res->set_height(height);
        attr_res->set_attr_key(block_msg.acc_attr_req().attr_key());
        attr_res->set_account(block_msg.acc_attr_req().account());
        transport::protobuf::Header msg;
        auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
        assert(dht_ptr != nullptr);
        BlockProto::CreateGetBlockResponse(
                dht_ptr->local_node(),
                header,
                block_msg_res.SerializeAsString(),
                msg);
        network::Route::Instance()->Send(msg);
    } else {
        protobuf::BlockMessage block_msg_res;
        auto attr_res = block_msg_res.mutable_acc_attr_res();
        attr_res->set_block("");
        attr_res->set_height(height);
        attr_res->set_attr_key(block_msg.acc_attr_req().attr_key());
        attr_res->set_account(block_msg.acc_attr_req().account());
        transport::protobuf::Header msg;
        auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
                network::kUniversalNetworkId);
        assert(dht_ptr != nullptr);
        BlockProto::CreateGetBlockResponse(
                dht_ptr->local_node(),
                header,
                block_msg_res.SerializeAsString(),
                msg);
        network::Route::Instance()->Send(msg);
    }
}

void BlockManager::HandleGetHeightRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    auto acc_ptr = AccountManager::Instance()->GetAcountInfo(
            block_msg.height_req().account_addr());
    if (acc_ptr == nullptr) {
        return;
    }
    protobuf::BlockMessage block_msg_res;
    auto height_res = block_msg_res.mutable_height_res();
	height_res->set_account_addr(block_msg.height_req().account_addr());
    auto priqueue = acc_ptr->get_height_pri_queue();
    while (!priqueue.empty()) {
        height_res->add_heights(priqueue.top());
        priqueue.pop();
    }

    transport::protobuf::Header msg;
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    BlockProto::CreateGetBlockResponse(
            dht_ptr->local_node(),
            header,
            block_msg_res.SerializeAsString(),
            msg);
    dht_ptr->SendToClosestNode(msg);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
}

void BlockManager::SendBlockNotExists(transport::protobuf::Header& header) {
    protobuf::BlockMessage block_msg_res;
    auto block_res = block_msg_res.mutable_block_res();
    block_res->set_block("");
    transport::protobuf::Header msg;
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
        network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    BlockProto::CreateGetBlockResponse(
            dht_ptr->local_node(),
            header,
            block_msg_res.SerializeAsString(),
            msg);
    dht_ptr->SendToClosestNode(msg);
}

int BlockManager::HandleGetBlockRequest(
        transport::protobuf::Header& header,
        protobuf::BlockMessage& block_msg) {
    std::string block_hash;
    if (block_msg.block_req().has_block_hash()) {
        block_hash = block_msg.block_req().block_hash();
    } else if (block_msg.block_req().has_tx_gid()) {
        std::string tx_gid;
        if (block_msg.block_req().from()) {
            tx_gid = common::GetTxDbKey(true, block_msg.block_req().tx_gid());
        } else {
            tx_gid = common::GetTxDbKey(false, block_msg.block_req().tx_gid());
        }
        auto st = db::Db::Instance()->Get(tx_gid, &block_hash);
        if (!st.ok()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("get block hash error", header);
            SendBlockNotExists(header);
            return kBlockError;
        }
    } else if (block_msg.block_req().has_height()) {
        if (!block_msg.block_req().has_account_address()) {
            return kBlockError;
        }
        uint32_t netid = network::GetConsensusShardNetworkId(
                block_msg.block_req().account_address());
        uint32_t pool_idx = common::GetPoolIndex(block_msg.block_req().account_address());
        std::string height_db_key = common::GetHeightDbKey(
                netid,
                pool_idx,
                block_msg.block_req().height());
        auto st = db::Db::Instance()->Get(height_db_key, &block_hash);
        if (!st.ok()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("get block hash error", header);
            SendBlockNotExists(header);
            return kBlockError;
        }
    }

    if (block_hash.empty()) {
        SendBlockNotExists(header);
        return kBlockError;
    }

    std::string block_data;
    auto st = db::Db::Instance()->Get(block_hash, &block_data);
    if (!st.ok()) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("get block data error", header);
        SendBlockNotExists(header);
        return kBlockError;
    }

    protobuf::BlockMessage block_msg_res;
    auto block_res = block_msg_res.mutable_block_res();
    block_res->set_block(block_data);
    transport::protobuf::Header msg;
    auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(
            network::kUniversalNetworkId);
    assert(dht_ptr != nullptr);
    BlockProto::CreateGetBlockResponse(
            dht_ptr->local_node(),
            header,
            block_msg_res.SerializeAsString(),
            msg);
    dht_ptr->SendToClosestNode(msg);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    return kBlockSuccess;
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

        if (LoadAllTx(last_block_hash, common::kTestForNetworkId, i) != kBlockSuccess) {
            BLOCK_ERROR("load tx from db failed!");
            return kBlockError;
        }
    }
    return kBlockSuccess;
}

int BlockManager::LoadAllTx(
        const std::string& frist_hash,
        uint32_t netid,
        uint32_t pool_index) {
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
        /*
        // for test just put
        std::string height_db_key = common::GetHeightDbKey(
                netid,
                pool_index,
                block_item.height());
        db::Db::Instance()->Put(height_db_key, block_item.hash());
        std::cout << "add height key: " << height_db_key << std::endl;
        */
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