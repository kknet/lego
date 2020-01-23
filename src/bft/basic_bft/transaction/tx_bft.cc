#include "stdafx.h"
#include "bft/basic_bft/transaction/tx_bft.h"

#include "common/global_info.h"
#include "contract/contract_manager.h"
#include "block/account_manager.h"
#include "network/network_utils.h"
#include "sync/key_value_sync.h"
#include "bft/bft_utils.h"
#include "bft/proto/bft.pb.h"
#include "bft/dispatch_pool.h"

namespace lego {

namespace bft {

TxBft::TxBft() {}

TxBft::~TxBft() {}

int TxBft::Init(bool leader) {
    std::vector<TxItemPtr> tx_vec;
    uint32_t pool_index = 0;
    DispatchPool::Instance()->GetTx(pool_index, tx_vec);
    if (tx_vec.empty()) {
        return kBftNoNewAccount;
    }
    return kBftSuccess;
}

int TxBft::Prepare(bool leader, std::string& prepare) {
    if (leader) {
        return LeaderCreatePrepare(prepare);
    }

    if (BackupCheckPrepare(prepare) != kBftSuccess) {
        return kBftError;
    }
    prepare = "";
    return kBftSuccess;
}

int TxBft::PreCommit(bool leader, std::string& pre_commit) {
    if (leader) {
        LeaderCreatePreCommit(pre_commit);
        return kBftSuccess;
    }

    pre_commit = "";
    return kBftSuccess;
}

int TxBft::Commit(bool leader, std::string& commit) {
    if (leader) {
        LeaderCreateCommit(commit);
        return kBftSuccess;
    }
    commit = "";
    return kBftSuccess;
}

int TxBft::LeaderCreatePrepare(std::string& bft_str) {
    uint32_t pool_index = 0;
    std::vector<TxItemPtr> tx_vec;
    DispatchPool::Instance()->GetTx(pool_index, tx_vec);
    if (tx_vec.empty()) {
        return kBftNoNewAccount;
    }

    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        add_item_index_vec(tx_vec[i]->index);
        push_bft_item_vec(tx_vec[i]->gid);
    }
    set_pool_index(pool_index);
    bft::protobuf::TxBft tx_bft;
    auto& ltx_prepare = *(tx_bft.mutable_ltx_prepare());
    TxProto::CreateTxBlock(pool_index, tx_vec, ltx_prepare);
    auto block_ptr = std::make_shared<bft::protobuf::Block>(ltx_prepare.block());
    SetBlock(block_ptr);
    bft_str = tx_bft.SerializeAsString();
    auto hash128 = common::Hash::Hash128(bft_str);
    set_prepare_hash(hash128);
    return kBftSuccess;
}

int TxBft::BackupCheckPrepare(std::string& bft_str) {
    bft::protobuf::BftMessage bft_msg;
    if (!bft_msg.ParseFromString(bft_str)) {
        BFT_ERROR("bft::protobuf::BftMessage ParseFromString failed!");
        return kBftInvalidPackage;
    }

    if (!bft_msg.has_data()) {
        BFT_ERROR("bft::protobuf::BftMessage has no data!");
        return kBftInvalidPackage;
    }

    bft::protobuf::TxBft tx_bft;
    if (!tx_bft.ParseFromString(bft_msg.data())) {
        BFT_ERROR("bft::protobuf::TxBft ParseFromString failed!");
        return kBftInvalidPackage;
    }

    if (!tx_bft.ltx_prepare().has_block()) {
        BFT_ERROR("prepare has no transaction!");
        return kBftInvalidPackage;
    }

    const auto& block = tx_bft.ltx_prepare().block();
    int res = CheckBlockInfo(block);
    if (res != kBftSuccess) {
        BFT_ERROR("bft check block info failed[%d]", res);
        return res;
    }

    std::unordered_map<std::string, int64_t> acc_balance_map;
    for (int32_t i = 0; i < block.tx_block().tx_list_size(); ++i) {
        const auto& tx_info = block.tx_block().tx_list(i);
        int tmp_res = CheckTxInfo(block, tx_info);
        if (tmp_res != kBftSuccess) {
            BFT_ERROR("check transaction failed![%d]", tmp_res);
            return tmp_res;
        }

        do {
            if (!tx_info.smart_contract_addr().empty()) {
                auto local_tx_info = DispatchPool::Instance()->GetTx(
                        pool_index(),
                        tx_info.to_add(),
                        tx_info.gid());
                if (local_tx_info == nullptr) {
                    BFT_ERROR("prepare [to: %d] [pool idx: %d] not has tx[%s]to[%s][%s]!",
                        tx_info.to_add(),
                        pool_index(),
                        common::Encode::HexEncode(tx_info.from()).c_str(),
                        common::Encode::HexEncode(tx_info.to()).c_str(),
                        common::Encode::HexEncode(tx_info.gid()).c_str());
                    return kBftTxNotExists;
                }

                if (contract::ContractManager::Instance()->Execute(
                        local_tx_info) != contract::kContractSuccess) {
                    if (tx_info.status() != kBftExecuteContractFailed) {
                        BFT_ERROR("local tx status not equal to leader status[%d][%d]!",
                            tx_info.status(), kBftExecuteContractFailed);
                        return kBftLeaderInfoInvalid;
                    }
                    break;
                }
            }

            if (tx_info.has_to() && !tx_info.to().empty()) {
                if (tx_info.to_add()) {
                    auto iter = acc_balance_map.find(tx_info.to());
                    if (iter == acc_balance_map.end()) {
                        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(tx_info.to());
                        if (acc_info == nullptr) {
                            if (tx_info.status() != kBftAccountNotExists) {
                                return kBftError;
                            }
                            break;
                        }
                        acc_balance_map[tx_info.to()] = acc_info->balance + tx_info.amount();
                    } else {
                        acc_balance_map[tx_info.to()] += tx_info.amount();
                    }

                    if (acc_balance_map[tx_info.to()] != static_cast<int64_t>(tx_info.balance())) {
                        BFT_ERROR("bft::protobuf::TxBft kBftAccountBalanceError failed!");
                        return kBftAccountBalanceError;
                    }
                } else {
                    auto iter = acc_balance_map.find(tx_info.from());
                    if (iter == acc_balance_map.end()) {
                        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(tx_info.from());
                        if (acc_info == nullptr) {
                            if (tx_info.status() != kBftAccountNotExists) {
                                return kBftError;
                            }
                            break;
                        }

                        if (acc_info->balance < static_cast<int64_t>(tx_info.amount())) {
                            if (tx_info.status() != kBftAccountBalanceError) {
                                return kBftError;
                            }
                            break;
                        }
                        acc_balance_map[tx_info.from()] = (
                                acc_info->balance - static_cast<int64_t>(tx_info.amount()));
                    } else {
                        if (acc_balance_map[tx_info.from()] <
                                static_cast<int64_t>(tx_info.amount())) {
                            if (tx_info.status() != kBftAccountBalanceError) {
                                return kBftError;
                            }
                            break;
                        }
                        acc_balance_map[tx_info.from()] -= static_cast<int64_t>(tx_info.amount());
                    }

                    if (acc_balance_map[tx_info.from()] != static_cast<int64_t>(tx_info.balance())) {
                        BFT_ERROR("bft::protobuf::TxBft kBftAccountBalanceError failed!");
                        return kBftAccountBalanceError;
                    }
                }
            }
        } while (0);
        
        push_bft_item_vec(tx_info.gid());
    }

    auto block_ptr = std::make_shared<bft::protobuf::Block>(block);
    SetBlock(block_ptr);
    return kBftSuccess;
}

int TxBft::CheckBlockInfo(const protobuf::Block& block_info) {
    // check hash
    auto src_str = block_info.tx_block().SerializeAsString();
    auto hash256 = common::Hash::Hash256(src_str);
    if (hash256 != block_info.hash()) {
        return kBftBlockHashError;
    }

    auto block_ptr = block::AccountManager::Instance()->GetBlockInfo(pool_index());
    if (block_ptr == nullptr) {
        return kBftBlockNotExists;
    }

    if (block_ptr->hash != block_info.tx_block().prehash()) {
        sync::KeyValueSync::Instance()->AddSync(
                block_info.tx_block().network_id(),
                block_info.tx_block().prehash(),
                sync::kSyncHighest);
        return kBftBlockPreHashError;
    }

    if (block_ptr->height + 1 != block_info.height()) {
        return kBftBlockHeightError;
    }
    return kBftSuccess;
}

int TxBft::CheckTxInfo(
        const protobuf::Block& block_info,
        const protobuf::TxInfo& tx_info) {
    auto local_tx_info = DispatchPool::Instance()->GetTx(
            pool_index(),
            tx_info.to_add(),
            tx_info.gid());
    if (local_tx_info == nullptr) {
        BFT_ERROR("prepare [to: %d] [pool idx: %d] not has tx[%s]to[%s][%s]!",
                tx_info.to_add(),
                pool_index(),
                common::Encode::HexEncode(tx_info.from()).c_str(),
                common::Encode::HexEncode(tx_info.to()).c_str(),
                common::Encode::HexEncode(tx_info.gid()).c_str());
        return kBftTxNotExists;
    }

    if (local_tx_info->lego_count != tx_info.amount()) {
        BFT_ERROR("local tx balance[%llu] not equal to leader[%llu]!",
                local_tx_info->lego_count, tx_info.amount());
        return kBftLeaderInfoInvalid;
    }

    if (local_tx_info->from_acc_addr != tx_info.from()) {
        BFT_ERROR("local tx  from not equal to leader from account!");
        return kBftLeaderInfoInvalid;
    }

    if (local_tx_info->to_acc_addr != tx_info.to()) {
        BFT_ERROR("local tx  to not equal to leader to account!");
        return kBftLeaderInfoInvalid;
    }

    if (local_tx_info->smart_contract_addr != tx_info.smart_contract_addr()) {
        BFT_ERROR("local tx smart_contract_addr[%s] not equal to leader to account [%s]!",
                local_tx_info->smart_contract_addr.c_str(),
                tx_info.smart_contract_addr().c_str());
        return kBftLeaderInfoInvalid;
    }

    if (local_tx_info->attr_map.size() != static_cast<uint32_t>(tx_info.attr_size())) {
        BFT_ERROR("local tx attrs not equal to leader attrs[%d][%d]!",
                local_tx_info->attr_map.size(), tx_info.attr_size());
        return kBftLeaderInfoInvalid;
    }

    for (int32_t i = 0; i < tx_info.attr_size(); ++i) {
        auto iter = local_tx_info->attr_map.find(tx_info.attr(i).key());
        if (iter == local_tx_info->attr_map.end()) {
            BFT_ERROR("local tx bft key[%s] not equal to leader key!",
                    tx_info.attr(i).key().c_str());
            return kBftLeaderInfoInvalid;
        }

        if (iter->second != tx_info.attr(i).value()) {
            BFT_ERROR("local tx bft value[%s] not equal to leader value[%s]!",
                    iter->second.c_str(), tx_info.attr(i).value().c_str());
            return kBftLeaderInfoInvalid;
        }
    }

    if (local_tx_info->bft_type != tx_info.type()) {
        BFT_ERROR("local tx bft type not equal to leader tx bft type!");
        return kBftLeaderInfoInvalid;
    }

    block::AccountInfoPtr acc_ptr{ nullptr };
    if (tx_info.has_to() && !tx_info.to().empty()) {

    } else {
        // check amount is 0
        // new account address
        if (common::GetPoolIndex(tx_info.from()) != pool_index()) {
            return kBftPoolIndexError;
        }

// 		if (common::GlobalInfo::Instance()->network_id() != network::kRootCongressNetworkId) {
// 			BFT_ERROR("create account address must root conngress.not[%u]",
// 				common::GlobalInfo::Instance()->network_id());
// 			return kBftNetwokInvalid;
// 		}

//         acc_ptr = block::AccountManager::Instance()->GetAcountInfo(tx_info.from());
//         if (acc_ptr != nullptr) {
//             return kBftAccountExists;
//         }

// 		auto hash_network_id = network::GetConsensusShardNetworkId(tx_info.from());
// 		if (hash_network_id != tx_info.netwok_id()) {
// 			BFT_ERROR("backup compute network id[%u] but leader[%u]",
// 					hash_network_id, tx_info.netwok_id());
// 			return kBftNetwokInvalid;
// 		}
//         if (tx_info.amount() != 0 || tx_info.balance() != 0) {
//             return kBftAccountBalanceError;
//         }
    }

    auto block_ptr = block::AccountManager::Instance()->GetBlockInfo(pool_index());
    if (block_ptr == nullptr) {
        return kBftBlockHeightError;
    }

    if (block_ptr->height + 1 != block_info.height()) {
        BFT_ERROR("block height error:[now: %d][leader: %d]",
                (block_ptr->height + 1),
                block_info.height());
        sync::KeyValueSync::Instance()->AddSync(
                block_info.tx_block().network_id(),
                block_info.hash(),
                sync::kSyncHighest);
        return kBftBlockHeightError;
    }
    return kBftSuccess;
}

int TxBft::LeaderCreatePreCommit(std::string& bft_str) {
    bft::protobuf::BftMessage bft_msg;
    bft_str = bft_msg.SerializeAsString();
    return kBftSuccess;
}

int TxBft::LeaderCreateCommit(std::string& bft_str) {
    bft::protobuf::BftMessage bft_msg;
    bft_str = bft_msg.SerializeAsString();
    return kBftSuccess;
}

}  // namespace bft

}  //namespace lego
