#include "bft/bft_manager.h"

#include <cassert>

#include "common/hash.h"
#include "common/global_info.h"
#include "statistics/statistics.h"
#include "block/block_manager.h"
#include "security/schnorr.h"
#include "dht/base_dht.h"
#include "election/elect_dht.h"
#include "network/dht_manager.h"
#include "network/route.h"
#include "network/universal_manager.h"
#include "bft/bft_utils.h"
#include "bft/basic_bft/transaction/tx_pool_manager.h"
#include "bft/basic_bft/transaction/tx_bft.h"
#include "bft/member_manager.h"
#include "bft/proto/bft_proto.h"
#include "bft/dispatch_pool.h"

namespace lego {

namespace bft {

BftManager::BftManager() {
    network::Route::Instance()->RegisterMessage(
            common::kBftMessage,
            std::bind(&BftManager::HandleMessage, this, std::placeholders::_1));
    timeout_tick_.CutOff(
            kBftTimeoutCheckPeriod,
            std::bind(&BftManager::CheckTimeout, this));
    mem_manager_ = std::make_shared<MemberManager>();
}

BftManager::~BftManager() {}

BftManager* BftManager::Instance() {
    static BftManager ins;
    return &ins;
}

void BftManager::NetworkMemberChange(
        uint32_t network_id,
        MembersPtr& members_ptr,
        NodeIndexMapPtr& node_index_map) {
    mem_manager_->SetNetworkMember(network_id, members_ptr, node_index_map);
}

uint32_t BftManager::GetMemberIndex(uint32_t network_id, const std::string& node_id) {
    return mem_manager_->GetMemberIndex(network_id, node_id);
}

void BftManager::HandleMessage(transport::protobuf::Header& header) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("HandleMessage", header);
    assert(header.type() == common::kBftMessage);
    bft::protobuf::BftMessage bft_msg;
    if (!bft_msg.ParseFromString(header.data())) {
        BFT_ERROR("protobuf::BftMessage ParseFromString failed!");
        return;
    }

    if (!bft_msg.has_status()) {
        return;
    }

	// TODO: check account address's network id valid. and this node is valid bft node
    if (bft_msg.status() == kBftInit) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("InitBft", header);
        InitBft(header, bft_msg);
        return;
    }

    if (bft_msg.status() == kBftToTxInit) {
        HandleToAccountTxBlock(header, bft_msg);
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("kBftToTxInit", header);
        return;
    }

    BftInterfacePtr bft_ptr = nullptr;
    if (bft_msg.status() == kBftPrepare && !bft_msg.leader()) {
        if (bft_msg.bft_address() == kTransactionPbftAddress) {
            bft_ptr = std::make_shared<TxBft>();
            bft_ptr->set_gid(bft_msg.gid());
            bft_ptr->set_network_id(bft_msg.net_id());
            bft_ptr->set_randm_num(bft_msg.rand());
            bft_ptr->set_pool_index(bft_msg.pool_index());
            bft_ptr->set_status(kBftPrepare);
            bft_ptr->set_member_count(3);
            bft_ptr->set_mem_manager(mem_manager_);
            if (!bft_ptr->CheckLeaderPrepare(bft_msg)) {
                LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE(
                        "BackupPrepare leader invalid", bft_ptr, header);
                return;
            }
            LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("BackupPrepare ok", bft_ptr, header);
            AddBft(bft_ptr);
        } else {
            assert(false);
        }
    } else {
        bft_ptr = GetBft(bft_msg.gid());
        if (bft_ptr == nullptr) {
            bft_ptr = std::make_shared<TxBft>();
            bft_ptr->set_gid(bft_msg.gid());
            bft_ptr->set_network_id(bft_msg.net_id());
            bft_ptr->set_randm_num(bft_msg.rand());
            bft_ptr->set_pool_index(bft_msg.pool_index());
            bft_ptr->set_status(bft_msg.status());
            bft_ptr->set_member_count(3);
            LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE(
                    "no bft end: ", bft_ptr, header);
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("no bft end", header);
            return;
        }
    }

    if (!bft_ptr) {
        assert(bft_ptr);
        return;
    }

    switch (bft_msg.status()) {
    case kBftPrepare: {
        if (!bft_msg.leader()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("BackupPrepare end", header);
            LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("BackupPrepare", bft_ptr, header);
            BackupPrepare(bft_ptr, header, bft_msg);
        } else {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("LeaderPrecommit end", header);
            LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("LeaderPrecommit", bft_ptr, header);
            LeaderPrecommit(bft_ptr, header, bft_msg);
        }
        break;
    }
    case kBftPreCommit: {
        if (!bft_msg.leader()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("BackupPrecommit end", header);
            LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("BackupPrecommit", bft_ptr, header);
            BackupPrecommit(bft_ptr, header, bft_msg);
        } else {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("LeaderCommit end", header);
            LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("LeaderCommit", bft_ptr, header);
            LeaderCommit(bft_ptr, header, bft_msg);
        }
        break;
    }
    case kBftCommit: {
        if (!bft_msg.leader()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("BackupCommit end", header);
            LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("BackupCommit", bft_ptr, header);
            BackupCommit(bft_ptr, header, bft_msg);
        } else {
            assert(false);
        }
        break;
    }
    default:
        std::cout << "get invalid bft status: " << bft_msg.status() << std::endl;
        assert(false);
        break;
    }
}

void BftManager::HandleToAccountTxBlock(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    uint32_t mem_index = GetMemberIndex(bft_msg.net_id(), bft_msg.node_id());
    if (mem_index == kInvalidMemberIndex) {
        return;
    }

    security::Signature sign;
    if (VerifySignature(mem_index, bft_msg, sign) != kBftSuccess) {
        BFT_ERROR("verify signature error!");
        return;
    }

    protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("paser fail", header);
        return;
    }

    if (!(tx_bft.has_to_tx() &&
            tx_bft.to_tx().has_block() &&
            tx_bft.to_tx().block().has_tx_block())) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("not to", header);
        return;
    }

    auto& tx_list = *(tx_bft.mutable_to_tx()->mutable_block()->mutable_tx_block()->mutable_tx_list());
    if (tx_list.empty()) {
        BFT_ERROR("to has no transaction info!");
        return;
    }
    // check aggsign
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].to().empty() || tx_list[i].to_add()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("not to", header);
            continue;
        }
        tx_list[i].set_to_add(true);

        // (TODO): check is this network
        if (network::GetConsensusShardNetworkId(tx_list[i].to()) != 4) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("network id error", header);
            continue;
        }

        if (DispatchPool::Instance()->Dispatch(tx_list[i]) != kBftSuccess) {
            BFT_ERROR("dispatch pool failed!");
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("dispatch error", header);
        }

        if (!mem_manager_->IsLeader(4, common::GlobalInfo::Instance()->id(), 0)) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("dispatch error", header);
            continue;
        }

        int res = StartBft(kTransactionPbftAddress, "", 4, 0);
        if (res != kBftSuccess) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("to leader start bft failed.", header);
        }
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("to leader start bft succ", header);
    }
}

int BftManager::InitBft(
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (VerifySignatureWithBftMessage(bft_msg) != kBftSuccess) {
        BFT_ERROR("verify signature with bft message failed!");
        return kBftError;
    }

    if (DispatchPool::Instance()->Dispatch(header, bft_msg) != kBftSuccess) {
        BFT_ERROR("dispatch pool failed!");
    }

    if (!mem_manager_->IsLeader(
            bft_msg.net_id(),
            common::GlobalInfo::Instance()->id(),
            bft_msg.rand())) {
        return kBftSuccess;
    }

    int res = StartBft(
            bft_msg.bft_address(),
            bft_msg.gid(),
            bft_msg.net_id(),
            bft_msg.rand());
    if (res != kBftSuccess) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("leader start bft failed.", header);
        if (res != kBftNoNewAccount) {
            BFT_WARN("start bft[%s][%s][%u][%llu] failed![%d]",
                common::Encode::HexEncode(bft_msg.bft_address()).c_str(),
                bft_msg.gid().c_str(),
                bft_msg.net_id(),
                bft_msg.rand(),
                res);
        }
        return kBftError;
    }
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("leader start bft succ", header);
    return kBftSuccess;
}

int BftManager::StartBft(
        const std::string& bft_address,
        const std::string& gid,
        uint32_t network_id,
        uint64_t rand_num) {
    BftInterfacePtr bft_ptr = nullptr;
    if (bft_address == kTransactionPbftAddress) {
        bft_ptr = std::make_shared<TxBft>();
        bft_ptr->set_gid(common::GlobalInfo::Instance()->gid());
        bft_ptr->set_network_id(network_id);
        bft_ptr->set_randm_num(rand_num);
        bft_ptr->set_mem_manager(mem_manager_);
        bft_ptr->set_member_count(3);
    } else {
        return kBftNotExists;
    }

    assert(bft_ptr);
    if (bft_ptr == nullptr) {
        return kBftError;
    }

    int leader_pre = LeaderPrepare(bft_ptr);
    if (leader_pre != kBftSuccess) {
        return leader_pre;
    }

    int res = AddBft(bft_ptr);
    if (res != kBftSuccess) {
        return res;
    }
    return kBftSuccess;
}

int BftManager::AddBft(BftInterfacePtr& bft_ptr) {
    std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
    auto iter = bft_hash_map_.find(bft_ptr->gid());
    if (iter != bft_hash_map_.end()) {
        return kBftAdded;
    }

    bft_hash_map_[bft_ptr->gid()] = bft_ptr;
    return kBftSuccess;
}

BftInterfacePtr BftManager::GetBft(const std::string& gid) {
    std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
    auto iter = bft_hash_map_.find(gid);
    if (iter == bft_hash_map_.end()) {
        return nullptr;
    }
    return iter->second;
}

void BftManager::RemoveBft(const std::string& gid) {
    BftInterfacePtr bft_ptr{ nullptr };
    {
        std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
        auto iter = bft_hash_map_.find(gid);
        if (iter != bft_hash_map_.end()) {
            bft_ptr = iter->second;
            bft_hash_map_.erase(iter);
        }
    }

    if (bft_ptr) {
        DispatchPool::Instance()->BftOver(bft_ptr);
        LEGO_BFT_DEBUG_FOR_CONSENSUS("remove", bft_ptr);
    }
}

int BftManager::LeaderPrepare(BftInterfacePtr& bft_ptr) {
    if (mem_manager_->IsLeader(
            bft_ptr->network_id(),
            common::GlobalInfo::Instance()->id(),
            bft_ptr->rand_num())) {
        std::string prepare_data;
        int res = bft_ptr->Prepare(true, prepare_data);
        LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE(
                std::string("LeaderPrepare ok:") + std::to_string(res),
                bft_ptr,
                msg);

        if (res != kBftSuccess) {
            return res;
        }

        uint32_t member_idx = GetMemberIndex(
                bft_ptr->network_id(),
                common::GlobalInfo::Instance()->id());
        if (member_idx == kInvalidMemberIndex) {
            return kBftError;
        }
        security::Signature leader_sig;
        if (!security::Schnorr::Instance()->Sign(
                bft_ptr->prepare_hash(),
                *(security::Schnorr::Instance()->prikey()),
                *(security::Schnorr::Instance()->pubkey()),
                leader_sig)) {
            BFT_ERROR("leader signature error.");
            return kBftError;
        }
        bft_ptr->LeaderPrecommitOk(member_idx, true, bft_ptr->secret());
        transport::protobuf::Header msg;
        auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
        auto local_node = dht_ptr->local_node();
        BftProto::LeaderCreatePrepare(
                local_node,
                prepare_data,
                bft_ptr,
                leader_sig,
                msg);
        network::Route::Instance()->Send(msg);
        bft_ptr->init_prepare_timeout();
        LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("LeaderPrepare ok", bft_ptr, msg);
        return kBftSuccess;
    } 
    return kBftError;
}

int BftManager::BackupPrepare(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    auto& data = *(header.mutable_data());
    if (bft_ptr->Prepare(false, data) != kBftSuccess) {
        BFT_ERROR("bft backup prepare failed!");
        std::string rand_num_str = std::to_string(rand() % std::numeric_limits<int>::max());
        BftProto::BackupCreatePrepare(
                header,
                bft_msg,
                local_node,
                rand_num_str,
                bft_ptr->secret(),
                false,
                msg);
        RemoveBft(bft_ptr->gid());
        LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("BackupPrepare error", bft_ptr, header);
    } else {
        BftProto::BackupCreatePrepare(
                header,
                bft_msg,
                local_node,
                data,
                bft_ptr->secret(),
                true,
                msg);
        LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("BackupPrepare succ", bft_ptr, header);
    }

    if (!msg.has_data()) {
        BFT_ERROR("message set data failed!");
        return kBftError;
    }
    bft_ptr->set_status(kBftPreCommit);
    // send prepare to leader
    dht_ptr->SendToClosestNode(msg);
    return kBftSuccess;
}

int BftManager::LeaderPrecommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    auto& data = *(header.mutable_data());
    if (bft_ptr->PreCommit(true, data) != kBftSuccess) {
        BFT_ERROR("bft leader pre-commit failed!");
        return kBftError;
    }

    uint32_t mem_index = GetMemberIndex(bft_msg.net_id(), bft_msg.node_id());
    if (mem_index == kInvalidMemberIndex) {
        return kBftError;
    }

    security::Signature sign;
    if (VerifySignature(mem_index, bft_msg, sign) != kBftSuccess) {
        BFT_ERROR("verify signature error!");
        return kBftError;
    }

    if (!bft_msg.has_secret()) {
        BFT_ERROR("backup prepare must has commit secret.");
        return kBftError;
    }
    security::CommitSecret backup_secret(bft_msg.secret());
    int res = bft_ptr->LeaderPrecommitOk(mem_index, bft_msg.agree(), backup_secret);
    if (res == kBftAgree) {
        // check pre-commit multi sign
        bft_ptr->init_precommit_timeout();
        uint32_t member_idx = GetMemberIndex(
                bft_ptr->network_id(),
                common::GlobalInfo::Instance()->id());
        if (member_idx == kInvalidMemberIndex) {
            return kBftError;
        }
        security::Response sec_res(
                bft_ptr->secret(),
                bft_ptr->challenge(),
                *(security::Schnorr::Instance()->prikey()));
        if (bft_ptr->LeaderCommitOk(member_idx, true, sec_res) == kBftOppose) {
            BFT_ERROR("leader commit failed!");
            RemoveBft(bft_ptr->gid());
            return kBftError;
        }
        transport::protobuf::Header msg;
        BftProto::LeaderCreatePreCommit(local_node, bft_ptr, msg);
        network::Route::Instance()->Send(msg);
        LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("LeaderPrecommit agree", bft_ptr, msg);
    } else if (res == kBftOppose) {
        RemoveBft(bft_ptr->gid());
        LEGO_BFT_DEBUG_FOR_CONSENSUS("LeaderPrecommit oppose", bft_ptr);
    } else {
        LEGO_BFT_DEBUG_FOR_CONSENSUS("LeaderPrecommit waiting", bft_ptr);
        // continue waiting, do nothing.
    }
    // broadcast pre-commit to backups
    return kBftSuccess;
}

int BftManager::BackupPrecommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (VerifyLeaderSignature(bft_ptr, bft_msg) != kBftSuccess) {
        BFT_ERROR("check leader signature error!");
        return kBftError;
    }

    if (!bft_msg.has_challenge()) {
        BFT_ERROR("leader pre commit message must has challenge.");
        return false;
    }

    security::Challenge agg_challenge(bft_msg.challenge());
    security::Response agg_res(
            bft_ptr->secret(),
            agg_challenge,
            *(security::Schnorr::Instance()->prikey()));
    // check prepare multi sign
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    auto& data = *(header.mutable_data());
    if (bft_ptr->PreCommit(false, data) != kBftSuccess) {
        BFT_ERROR("bft backup pre-commit failed!");
        std::string rand_num_str = std::to_string(rand() % std::numeric_limits<int>::max());
        BftProto::BackupCreatePreCommit(
                header,
                bft_msg,
                local_node,
                rand_num_str,
                agg_res,
                false,
                msg);
        RemoveBft(bft_ptr->gid());
        LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("BackupPrecommit error", bft_ptr, header);
    } else {
        BftProto::BackupCreatePreCommit(header, bft_msg, local_node, data, agg_res, true, msg);
        LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("BackupPrecommit succ", bft_ptr, header);
    }

    if (!msg.has_data()) {
        return kBftError;
    }
    bft_ptr->set_status(kBftCommit);
    // send pre-commit to leader
    dht_ptr->SendToClosestNode(msg);
    return kBftSuccess;
}

int BftManager::LeaderCommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    uint32_t mem_index = GetMemberIndex(bft_msg.net_id(), bft_msg.node_id());
    if (mem_index == kInvalidMemberIndex) {
        return kBftError;
    }

    security::Signature sign;
    if (VerifySignature(mem_index, bft_msg, sign) != kBftSuccess) {
        BFT_ERROR("verify signature error!");
        return kBftError;
    }

    if (!bft_msg.has_response()) {
        BFT_ERROR("backup pre commit message must have response.");
        return kBftError;
    }

    security::Response agg_res(bft_msg.response());
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    auto& data = *(header.mutable_data());
    if (bft_ptr->Commit(true, data) != kBftSuccess) {
        BFT_ERROR("bft leader commit failed!");
        return kBftError;
    }

    int res = bft_ptr->LeaderCommitOk(mem_index, bft_msg.agree(), agg_res);
    if (res == kBftAgree) {
        // check pre-commit multi sign and leader commit
        transport::protobuf::Header msg;
        BftProto::LeaderCreateCommit(local_node, bft_ptr, msg);
        if (!msg.has_data()) {
            BFT_ERROR("leader create commit message failed!");
            return kBftError;
        }

        if (block::BlockManager::Instance()->AddNewBlock(
                *(bft_ptr->prpare_block())) != block::kBlockSuccess) {
            BFT_ERROR("leader add block to db failed!");
            return kBftError;
        }
        network::Route::Instance()->Send(msg);
        LeaderBroadcastToAcc(bft_ptr->prpare_block());
        RemoveBft(bft_ptr->gid());
        statis::Statistics::Instance()->inc_period_tx_count(
                bft_ptr->prpare_block()->tx_block().tx_list_size());
        LEGO_BFT_DEBUG_FOR_CONSENSUS_AND_MESSAGE("LeaderCommit aggree", bft_ptr, msg);
    }  else if (res == kBftReChallenge) {
        transport::protobuf::Header msg;
        BftProto::LeaderCreatePreCommit(local_node, bft_ptr, msg);
        LEGO_BFT_DEBUG_FOR_CONSENSUS("LeaderCommit rechallenge", bft_ptr);
        network::Route::Instance()->Send(msg);
    } else if (res == kBftOppose) {
        RemoveBft(bft_ptr->gid());
        LEGO_BFT_DEBUG_FOR_CONSENSUS("LeaderCommit oppose", bft_ptr);
    } else {
        // continue waiting, do nothing.
        LEGO_BFT_DEBUG_FOR_CONSENSUS("LeaderCommit waiting", bft_ptr);
    }
    return kBftSuccess;
}

int BftManager::BackupCommit(
        BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& header,
        bft::protobuf::BftMessage& bft_msg) {
    if (VerifyLeaderSignature(bft_ptr, bft_msg) != kBftSuccess) {
        BFT_ERROR("check leader signature error!");
        return kBftError;
    }
    
    if (VerifyAggSignature(bft_ptr, bft_msg) != kBftSuccess) {
        BFT_ERROR("check bft agg signature error!");
        return kBftError;
    }
    auto dht_ptr = network::DhtManager::Instance()->GetDht(bft_ptr->network_id());
    auto local_node = dht_ptr->local_node();
    transport::protobuf::Header msg;
    auto& data = *(header.mutable_data());
    if (bft_ptr->Commit(false, data) != kBftSuccess) {
        BFT_ERROR("bft backup commit failed!");
    }

    if (block::BlockManager::Instance()->AddNewBlock(
            *(bft_ptr->prpare_block())) != block::kBlockSuccess) {
        BFT_ERROR("backup add block to db failed!");
        return kBftError;
    }

    LeaderBroadcastToAcc(bft_ptr->prpare_block());
    LEGO_BFT_DEBUG_FOR_CONSENSUS("BackupCommit", bft_ptr);
    statis::Statistics::Instance()->inc_period_tx_count(
            bft_ptr->prpare_block()->tx_block().tx_list_size());
    std::cout << "backup commit ok." << std::endl;
    RemoveBft(bft_ptr->gid());
    // start new bft
    return kBftSuccess;
}

void BftManager::LeaderBroadcastToAcc(const std::shared_ptr<bft::protobuf::Block>& block_ptr) {
    if (!mem_manager_->IsLeader(4, common::GlobalInfo::Instance()->id(), 0)) {
        return;
    }

    std::set<uint32_t> broadcast_nets;
    auto tx_list = block_ptr->tx_block().tx_list();
    for (int32_t i = 0; i < tx_list.size(); ++i) {
        if (tx_list[i].has_to() && !tx_list[i].to_add()) {
            broadcast_nets.insert(network::GetConsensusShardNetworkId(tx_list[i].to()));
        }
    }

    for (auto iter = broadcast_nets.begin(); iter != broadcast_nets.end(); ++iter) {
        transport::protobuf::Header msg;
        auto dht_ptr = network::UniversalManager::Instance()->GetUniversal(network::kUniversalNetworkId);
        if (!dht_ptr) {
            assert(false);
            continue;
        }

        auto local_node = dht_ptr->local_node();
        BftProto::CreateLeaderBroadcastToAccount(local_node, *iter, block_ptr, msg);
        network::Route::Instance()->Send(msg);
        network::Route::Instance()->SendToLocal(msg);
    }
}

void BftManager::CheckTimeout() {
    std::vector<BftInterfacePtr> timeout_vec;
    {
        std::lock_guard<std::mutex> guard(bft_hash_map_mutex_);
        for (auto iter = bft_hash_map_.begin(); iter != bft_hash_map_.end();) {
            if (iter->second->timeout()) {
                timeout_vec.push_back(iter->second);
                bft_hash_map_.erase(iter++);
                continue;
            }
            ++iter;
        }
    }

    for (uint32_t i = 0; i < timeout_vec.size(); ++i) {
        DispatchPool::Instance()->BftOver(timeout_vec[i]);
        LEGO_BFT_DEBUG_FOR_CONSENSUS("Timeout", timeout_vec[i]);
    }
    timeout_tick_.CutOff(
            kBftTimeoutCheckPeriod,
            std::bind(&BftManager::CheckTimeout, this));
}

int BftManager::VerifySignatureWithBftMessage(const bft::protobuf::BftMessage& bft_msg) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    auto pubkey = security::PublicKey(bft_msg.pubkey());
    auto sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    auto sha128 = common::Hash::Hash128(bft_msg.data());
    if (!security::Schnorr::Instance()->Verify(sha128, sign, pubkey)) {
        BFT_ERROR("check signature error!");
        return kBftError;
    }
    return kBftSuccess;

}

int BftManager::VerifySignature(
        uint32_t mem_index,
        const bft::protobuf::BftMessage& bft_msg,
        security::Signature& sign) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }

    sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    auto mem_ptr = mem_manager_->GetMember(bft_msg.net_id(), mem_index);
    if (!mem_ptr) {
        return kBftError;
    }

    auto sha128 = common::Hash::Hash128(bft_msg.data());
    if (!security::Schnorr::Instance()->Verify(sha128, sign, mem_ptr->pubkey)) {
        BFT_ERROR("check signature error!");
        return kBftError;
    }
    return kBftSuccess;
}

int BftManager::VerifyLeaderSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg) {
    if (!bft_msg.has_sign_challenge() || !bft_msg.has_sign_response()) {
        BFT_ERROR("backup has no sign");
        return kBftError;
    }
    auto sign = security::Signature(bft_msg.sign_challenge(), bft_msg.sign_response());
    auto mem_ptr = mem_manager_->GetMember(bft_msg.net_id(), bft_ptr->leader_index());
    if (!mem_ptr) {
        return kBftError;
    }

    if (!security::Schnorr::Instance()->Verify(
            bft_ptr->prepare_hash(),
            sign,
            mem_ptr->pubkey)) {
        BFT_ERROR("check signature error!");
        return kBftError;
    }
    return kBftSuccess;
}

int BftManager::VerifyAggSignature(
        BftInterfacePtr& bft_ptr,
        const bft::protobuf::BftMessage& bft_msg) {
    if (bft_ptr->BackupCheckAggSign(bft_msg) != kBftSuccess) {
        BFT_ERROR("check agg sign failed!");
        return kBftError;
    }
    return kBftSuccess;
}

}  // namespace bft

}  // namespace lego
