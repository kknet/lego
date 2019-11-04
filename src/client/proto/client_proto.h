#pragma once

#include "common/global_info.h"
#include "common/user_property_key_define.h"
#include "security/schnorr.h"
#include "transport/proto/transport.pb.h"
#include "transport/transport_utils.h"
#include "dht/node.h"
#include "dht/dht_key.h"
#include "client/proto/client.pb.h"
#include "client/client_utils.h"

namespace lego {

namespace client {

class ClientProto {
public:
    static void SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
        broad_param->set_layer_left(0);
        broad_param->set_layer_right((std::numeric_limits<uint64_t>::max)());
        broad_param->set_ign_bloomfilter_hop(kBftBroadcastIgnBloomfilterHop);
        broad_param->set_stop_times(kBftBroadcastStopTimes);
        broad_param->set_hop_limit(kBftHopLimit);
        broad_param->set_hop_to_layer(kBftHopToLayer);
        broad_param->set_neighbor_count(kBftNeighborCount);
    }

    static void CreateGetVpnInfoRequest(
            const dht::NodePtr& local_node,
            const dht::NodePtr& des_node,
            uint32_t msg_id,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        msg.set_des_dht_key(des_node->dht_key);
        msg.set_des_dht_key_hash(des_node->dht_key_hash);
        msg.set_priority(transport::kTransportPriorityMiddle);
        msg.set_id(msg_id);
        msg.set_type(common::kServiceMessage);
        msg.set_client(local_node->client_mode);
        msg.set_hop_count(0);
        protobuf::ServiceMessage svr_msg;
        auto vpn_req = svr_msg.mutable_vpn_req();
        vpn_req->set_pubkey(security::Schnorr::Instance()->str_pubkey());
        vpn_req->set_method("aes-128-cfb");
        msg.set_data(svr_msg.SerializeAsString());
    }

    static void CreateTxRequest(
            const dht::NodePtr& local_node,
            const std::string& gid,
            const std::string& to,
            uint64_t amount,
            uint64_t rand_num,
            uint32_t type,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        std::string account_address = network::GetAccountAddressByPublicKey(
                security::Schnorr::Instance()->str_pubkey());
        uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
        dht::DhtKeyManager dht_key(des_net_id, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityLowest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBftMessage);
        msg.set_client(false);
        msg.set_hop_count(0);
        auto broad_param = msg.mutable_broadcast();
        SetDefaultBroadcastParam(broad_param);
        protobuf::BftMessage bft_msg;
        bft_msg.set_gid(gid);
        bft_msg.set_rand(rand_num);
        bft_msg.set_status(kBftInit);
        bft_msg.set_leader(false);
        bft_msg.set_net_id(des_net_id);
        bft_msg.set_node_id(local_node->id);
        bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
        bft_msg.set_bft_address(kTransactionPbftAddress);
        protobuf::TxBft tx_bft;
        auto new_tx = tx_bft.mutable_new_tx();
        new_tx->set_gid(gid);
        new_tx->set_from_acc_addr(account_address);
        new_tx->set_from_pubkey(security::Schnorr::Instance()->str_pubkey());
        new_tx->set_to_acc_addr(to);
        new_tx->set_lego_count(amount);
        new_tx->set_type(type);
        auto data = tx_bft.SerializeAsString();
        bft_msg.set_data(data);
        auto hash128 = common::Hash::Hash128(data);
        
        security::Signature sign;
        auto& prikey = *security::Schnorr::Instance()->prikey();
        auto& pubkey = *security::Schnorr::Instance()->pubkey();
        if (!security::Schnorr::Instance()->Sign(
                hash128,
                prikey,
                pubkey,
                sign)) {
            CLIENT_ERROR("leader pre commit signature failed!");
            return;
        }
        std::string sign_challenge_str;
        std::string sign_response_str;
        sign.Serialize(sign_challenge_str, sign_response_str);
        bft_msg.set_sign_challenge(sign_challenge_str);
        bft_msg.set_sign_response(sign_response_str);
        msg.set_data(bft_msg.SerializeAsString());
    }

    static void CreateVpnLoginRequest(
            const dht::NodePtr& local_node,
            const std::string& gid,
            const std::string& svr_account,
            const std::vector<std::string>& route_accounts,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        std::string account_address = network::GetAccountAddressByPublicKey(
            security::Schnorr::Instance()->str_pubkey());
        uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
        dht::DhtKeyManager dht_key(des_net_id, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityLowest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBftMessage);
        msg.set_client(false);
        msg.set_hop_count(0);
        auto broad_param = msg.mutable_broadcast();
        SetDefaultBroadcastParam(broad_param);
        protobuf::BftMessage bft_msg;
        bft_msg.set_gid(gid);
        bft_msg.set_rand(0);
        bft_msg.set_status(kBftInit);
        bft_msg.set_leader(false);
        bft_msg.set_net_id(des_net_id);
        bft_msg.set_node_id(local_node->id);

        bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
        bft_msg.set_bft_address(kTransactionPbftAddress);
        protobuf::TxBft tx_bft;
        auto new_tx = tx_bft.mutable_new_tx();
        new_tx->set_gid(gid);
        new_tx->set_from_acc_addr(account_address);
        new_tx->set_from_pubkey(security::Schnorr::Instance()->str_pubkey());
        new_tx->set_type(common::kConsensusLogin);
        auto server_attr = new_tx->add_attr();
        server_attr->set_key(common::kVpnLoginAttrKey);
        server_attr->set_value(svr_account);
        auto data = tx_bft.SerializeAsString();
        bft_msg.set_data(data);
        auto hash128 = common::Hash::Hash128(data);

        security::Signature sign;
        auto& prikey = *security::Schnorr::Instance()->prikey();
        auto& pubkey = *security::Schnorr::Instance()->pubkey();
        if (!security::Schnorr::Instance()->Sign(
                hash128,
                prikey,
                pubkey,
                sign)) {
            CLIENT_ERROR("leader pre commit signature failed!");
            return;
        }
        std::string sign_challenge_str;
        std::string sign_response_str;
        sign.Serialize(sign_challenge_str, sign_response_str);
        bft_msg.set_sign_challenge(sign_challenge_str);
        bft_msg.set_sign_response(sign_response_str);
        msg.set_data(bft_msg.SerializeAsString());
    }

    static void CreateTransactionWithAttr(
            const dht::NodePtr& local_node,
            const std::string& gid,
            const std::string& to,
            int64_t amount,
            uint32_t type,
            const std::map<std::string, std::string>& attrs,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        std::string account_address = network::GetAccountAddressByPublicKey(
            security::Schnorr::Instance()->str_pubkey());
        uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
        dht::DhtKeyManager dht_key(des_net_id, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityLowest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBftMessage);
        msg.set_client(false);
        msg.set_hop_count(0);
        auto broad_param = msg.mutable_broadcast();
        SetDefaultBroadcastParam(broad_param);
        protobuf::BftMessage bft_msg;
        bft_msg.set_gid(gid);
        bft_msg.set_rand(0);
        bft_msg.set_status(kBftInit);
        bft_msg.set_leader(false);
        bft_msg.set_net_id(des_net_id);
        bft_msg.set_node_id(local_node->id);
        bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
        bft_msg.set_bft_address(kTransactionPbftAddress);
        protobuf::TxBft tx_bft;
        auto new_tx = tx_bft.mutable_new_tx();
        new_tx->set_gid(gid);
        new_tx->set_from_acc_addr(account_address);
        new_tx->set_from_pubkey(security::Schnorr::Instance()->str_pubkey());
        new_tx->set_type(type);
        new_tx->set_to_acc_addr(to);
        new_tx->set_lego_count(amount);

        for (auto iter = attrs.begin(); iter != attrs.end(); ++iter) {
            auto server_attr = new_tx->add_attr();
            server_attr->set_key(iter->first);
            server_attr->set_value(iter->second);
        }

        auto data = tx_bft.SerializeAsString();
        bft_msg.set_data(data);
        auto hash128 = common::Hash::Hash128(data);

        security::Signature sign;
        auto& prikey = *security::Schnorr::Instance()->prikey();
        auto& pubkey = *security::Schnorr::Instance()->pubkey();
        if (!security::Schnorr::Instance()->Sign(
                hash128,
                prikey,
                pubkey,
                sign)) {
            CLIENT_ERROR("leader pre commit signature failed!");
            return;
        }
        std::string sign_challenge_str;
        std::string sign_response_str;
        sign.Serialize(sign_challenge_str, sign_response_str);
        bft_msg.set_sign_challenge(sign_challenge_str);
        bft_msg.set_sign_response(sign_response_str);
        msg.set_data(bft_msg.SerializeAsString());
    }

	static void CreateClientNewVersion(
            const dht::NodePtr& local_node,
            const std::string& gid,
			const std::string& downurl,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        std::string account_address = network::GetAccountAddressByPublicKey(
            security::Schnorr::Instance()->str_pubkey());
        uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
        dht::DhtKeyManager dht_key(des_net_id, 0);
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityLowest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBftMessage);
        msg.set_client(false);
        msg.set_hop_count(0);
        auto broad_param = msg.mutable_broadcast();
        SetDefaultBroadcastParam(broad_param);
        protobuf::BftMessage bft_msg;
        bft_msg.set_gid(gid);
        bft_msg.set_rand(0);
        bft_msg.set_status(kBftInit);
        bft_msg.set_leader(false);
        bft_msg.set_net_id(des_net_id);
        bft_msg.set_node_id(local_node->id);
        bft_msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
        bft_msg.set_bft_address(kTransactionPbftAddress);
        protobuf::TxBft tx_bft;
        auto new_tx = tx_bft.mutable_new_tx();
        new_tx->set_gid(gid);
        new_tx->set_from_acc_addr(account_address);
        new_tx->set_from_pubkey(security::Schnorr::Instance()->str_pubkey());
        new_tx->set_type(common::kConsensusKeyValue);
		auto down_attr = new_tx->add_attr();
		down_attr->set_key("tenon_vpn_url");
		down_attr->set_value(downurl);
        auto data = tx_bft.SerializeAsString();
        bft_msg.set_data(data);
        auto hash128 = common::Hash::Hash128(data);

        security::Signature sign;
        auto& prikey = *security::Schnorr::Instance()->prikey();
        auto& pubkey = *security::Schnorr::Instance()->pubkey();
        if (!security::Schnorr::Instance()->Sign(
                hash128,
                prikey,
                pubkey,
                sign)) {
            CLIENT_ERROR("leader pre commit signature failed!");
            return;
        }
        std::string sign_challenge_str;
        std::string sign_response_str;
        sign.Serialize(sign_challenge_str, sign_response_str);
        bft_msg.set_sign_challenge(sign_challenge_str);
        bft_msg.set_sign_response(sign_response_str);
        msg.set_data(bft_msg.SerializeAsString());
    }

    static void GetBlockWithTxGid(
            const dht::NodePtr& local_node,
            const std::string& hash,
            bool is_gid,
            bool from,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        std::string account_address = network::GetAccountAddressByPublicKey(
                security::Schnorr::Instance()->str_pubkey());
        uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
        dht::DhtKeyManager dht_key(
                des_net_id,
                rand() % std::numeric_limits<uint8_t>::max());
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityLowest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBlockMessage);
        msg.set_client(local_node->client_mode);
        msg.set_hop_count(0);
        protobuf::BlockMessage block_msg;
        auto block_req = block_msg.mutable_block_req();
        if (is_gid) {
            block_req->set_tx_gid(hash);
        }else {
            block_req->set_block_hash(hash);
        }
        block_req->set_from(from);
        msg.set_data(block_msg.SerializeAsString());
    }

    static void GetAccountHeight(
            const dht::NodePtr& local_node,
            transport::protobuf::Header& msg,
			const std::string& account_address) {
        msg.set_src_dht_key(local_node->dht_key);
//         std::string account_address = network::GetAccountAddressByPublicKey(
//             security::Schnorr::Instance()->str_pubkey());
        uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
        dht::DhtKeyManager dht_key(
                des_net_id,
                common::GlobalInfo::Instance()->country());
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityLowest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBlockMessage);
        msg.set_client(local_node->client_mode);
        msg.set_hop_count(0);
        protobuf::BlockMessage block_msg;
        auto height_req = block_msg.mutable_height_req();
        height_req->set_account_addr(account_address);
        msg.set_data(block_msg.SerializeAsString());
    }

    static void GetBlockWithHeight(
            const dht::NodePtr& local_node,
			const std::string& account_address,
			uint64_t height,
            transport::protobuf::Header& msg) {
		msg.set_src_dht_key(local_node->dht_key);
        uint32_t des_net_id = network::GetConsensusShardNetworkId(account_address);
        dht::DhtKeyManager dht_key(
            des_net_id,
            rand() % std::numeric_limits<uint8_t>::max());
        msg.set_des_dht_key(dht_key.StrKey());
        msg.set_priority(transport::kTransportPriorityLowest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kBlockMessage);
        msg.set_client(local_node->client_mode);
        msg.set_hop_count(0);
        protobuf::BlockMessage block_msg;
        auto block_req = block_msg.mutable_block_req();
        block_req->set_height(height);
        block_req->set_account_address(account_address);
        msg.set_data(block_msg.SerializeAsString());
    }

    static void CreateVpnHeartbeat(
            const dht::NodePtr& local_node,
            const std::string& des_dht_key,
            transport::protobuf::Header& msg) {
        msg.set_src_dht_key(local_node->dht_key);
        msg.set_des_dht_key(des_dht_key);
        msg.set_priority(transport::kTransportPriorityLowest);
        msg.set_id(common::GlobalInfo::Instance()->MessageId());
        msg.set_type(common::kServiceMessage);
        msg.set_client(local_node->client_mode);
        msg.set_hop_count(0);
        protobuf::ServiceMessage svr_msg;
        auto vpn_req = svr_msg.mutable_vpn_req();
        vpn_req->set_pubkey(security::Schnorr::Instance()->str_pubkey());

        auto hash128 = common::Hash::Hash128(security::Schnorr::Instance()->str_pubkey());
        security::Signature sign;
        auto& prikey = *security::Schnorr::Instance()->prikey();
        auto& pubkey = *security::Schnorr::Instance()->pubkey();
        if (!security::Schnorr::Instance()->Sign(
                hash128,
                prikey,
                pubkey,
                sign)) {
            CLIENT_ERROR("leader pre commit signature failed!");
            return;
        }
        std::string sign_challenge_str;
        std::string sign_response_str;
        sign.Serialize(sign_challenge_str, sign_response_str);
        vpn_req->set_sign_challenge(sign_challenge_str);
        vpn_req->set_sign_response(sign_response_str);
        vpn_req->set_heartbeat(true);
        msg.set_data(svr_msg.SerializeAsString());
    }

private:
    ClientProto();
    ~ClientProto();

    DISALLOW_COPY_AND_ASSIGN(ClientProto);
};

}  // namespace client

}  // namespace lego
