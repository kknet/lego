#include "bft/basic_bft/transaction/proto/tx_proto.h"

#include "common/global_info.h"
#include "block/account_manager.h"
#include "transport/transport_utils.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "contract/contract_manager.h"
#include "bft/bft_utils.h"
#include "bft/basic_bft/transaction/proto/tx.pb.h"

namespace lego {

namespace bft {

void TxProto::SetDefaultBroadcastParam(
        transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right(((std::numeric_limits<uint64_t>::max))());
    broad_param->set_ign_bloomfilter_hop(kBftBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(kBftBroadcastStopTimes);
    broad_param->set_hop_limit(kBftHopLimit);
    broad_param->set_hop_to_layer(kBftHopToLayer);
    broad_param->set_neighbor_count(kBftNeighborCount);
}

// just for test
void TxProto::CreateTxRequest(
        const dht::NodePtr& local_node,
        const std::string& gid,
        uint64_t rand_num,
        transport::protobuf::Header& msg) {
    security::PrivateKey prikey;
    security::PublicKey pubkey(prikey);
    std::string str_pubkey;
    pubkey.Serialize(str_pubkey);

    msg.set_src_dht_key(local_node->dht_key);
    std::string account_address = network::GetAccountAddressByPublicKey(str_pubkey);
    uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
    dht::DhtKeyManager dht_key(des_net_id, 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityLowest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_gid(gid);
    bft_msg.set_rand(rand_num);
    bft_msg.set_status(kBftInit);
    bft_msg.set_leader(false);
    bft_msg.set_net_id(des_net_id);
    bft_msg.set_node_id(local_node->id);
    bft_msg.set_pubkey(str_pubkey);
    bft_msg.set_bft_address(kTransactionPbftAddress);
    protobuf::TxBft tx_bft;
    auto new_tx = tx_bft.mutable_new_tx();
    new_tx->set_gid(gid);
    new_tx->set_from_acc_addr(account_address);
    new_tx->set_from_pubkey(str_pubkey);
    new_tx->set_from_sign("from_sign");
    auto data = tx_bft.SerializeAsString();
    bft_msg.set_data(data);
    auto hash128 = common::Hash::Hash128(data);
    security::Signature sign;
    if (!security::Schnorr::Instance()->Sign(
            hash128,
            prikey,
            pubkey,
            sign)) {
        BFT_ERROR("leader pre commit signature failed!");
        return;
    }
    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("new account: ") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            common::Encode::HexEncode(dht_key.StrKey()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}

void TxProto::CreateTxBlock(
        uint32_t pool_idx,
        std::vector<TxItemPtr>& tx_vec,
        bft::protobuf::LeaderTxPrepare& bft_msg) {
    protobuf::Block& block_item = *(bft_msg.mutable_block());
    auto tx_block = block_item.mutable_tx_block();
    auto tx_list = tx_block->mutable_tx_list();
    std::unordered_map<std::string, int64_t> acc_balance_map;
    for (uint32_t i = 0; i < tx_vec.size(); ++i) {
        protobuf::TxInfo tx;
        tx.set_version(0);
        tx.set_gid(tx_vec[i]->gid);
        tx.set_from(tx_vec[i]->from_acc_addr);
        tx.set_from_pubkey(tx_vec[i]->from_pubkey);
        tx.set_from_sign(tx_vec[i]->from_sign);
        tx.set_to(tx_vec[i]->to_acc_addr);
        tx.set_amount(tx_vec[i]->lego_count);
        tx.set_gas_limit(0);
        tx.set_gas_price(0);
        tx.set_gas_used(0);
        tx.set_status(kBftSuccess);
        tx.set_to_add(tx_vec[i]->add_to_acc_addr);
        tx.set_smart_contract_addr(tx_vec[i]->smart_contract_addr);
        tx.set_type(tx_vec[i]->bft_type);

        do {
            if (tx_vec[i]->to_acc_addr.empty()) {
                tx.set_netwok_id(network::GetConsensusShardNetworkId(tx_vec[i]->from_acc_addr));
                tx.set_balance(0);  // create new account address
            } else {
                if (tx_vec[i]->add_to_acc_addr) {
                    auto iter = acc_balance_map.find(tx_vec[i]->to_acc_addr);
                    if (iter == acc_balance_map.end()) {
                        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(
                                tx_vec[i]->to_acc_addr);
                        if (acc_info == nullptr) {
                            // this should remove from tx pool
                            tx.set_status(kBftAccountNotExists);
                            break;
                        }
                        acc_balance_map[tx_vec[i]->to_acc_addr] = acc_info->balance + tx_vec[i]->lego_count;
                    } else {
                        acc_balance_map[tx_vec[i]->to_acc_addr] += tx_vec[i]->lego_count;
                    }
                    tx.set_balance(acc_balance_map[tx_vec[i]->to_acc_addr]);
                } else {
                    auto iter = acc_balance_map.find(tx_vec[i]->from_acc_addr);
                    if (iter == acc_balance_map.end()) {
                        auto acc_info = block::AccountManager::Instance()->GetAcountInfo(
                                tx_vec[i]->from_acc_addr);
                        if (acc_info == nullptr) {
                            // this should remove from tx pool
                            tx.set_status(kBftAccountNotExists);
                            break;
                        }

                        if (acc_info->balance < static_cast<int64_t>(tx_vec[i]->lego_count)) {
                            // this should remove from tx pool
                            tx.set_status(kBftAccountBalanceError);
                            break;
                        }
                        acc_balance_map[tx_vec[i]->from_acc_addr] = (
                                acc_info->balance - static_cast<int64_t>(tx_vec[i]->lego_count));
                    } else {
                        if (acc_balance_map[tx_vec[i]->from_acc_addr] <
                                static_cast<int64_t>(tx_vec[i]->lego_count)) {
                            // this should remove from tx pool
                            tx.set_status(kBftAccountBalanceError);
                            break;
                        }
                        acc_balance_map[tx_vec[i]->from_acc_addr] -=
                                static_cast<int64_t>(tx_vec[i]->lego_count);
                    }
                    tx.set_balance(acc_balance_map[tx_vec[i]->from_acc_addr]);
                }
            }

            // execute contract
            if (!tx_vec[i]->smart_contract_addr.empty()) {
                if (contract::ContractManager::Instance()->Execute(
                        tx_vec[i]) != contract::kContractSuccess) {
                    tx.set_status(kBftExecuteContractFailed);
                    break;
                }
            }
        } while (0);

        if (!tx_vec[i]->attr_map.empty()) {
            for (auto iter = tx_vec[i]->attr_map.begin();
                    iter != tx_vec[i]->attr_map.end(); ++iter) {
                auto tx_attr = tx.add_attr();
                tx_attr->set_key(iter->first);
                tx_attr->set_value(iter->second);
            }
        }
        auto add_tx = tx_list->Add();
        *add_tx = tx;
    }
    auto block_ptr = block::AccountManager::Instance()->GetBlockInfo(pool_idx);
    if (block_ptr == nullptr) {
        assert(false);
        return;
    }
    tx_block->set_prehash(block_ptr->hash);
    tx_block->set_version(0);
    tx_block->set_elect_ver(0);
    tx_block->set_rc_hash("");
    tx_block->set_tx_id(block_ptr->height + 1);
    tx_block->set_tx_hash("");
    tx_block->set_tx_root_hash("");
    tx_block->set_network_id(4);
    auto sha256 = common::Hash::Hash256(tx_block->SerializeAsString());
    block_item.set_hash(sha256);
    block_item.set_height(block_ptr->height + 1);
	block_item.set_timestamp(common::TimeStampMsec());
}

}  // namespace bft

}  // namespace lego
