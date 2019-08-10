#include "bft/proto/bft_proto.h"

#include "common/global_info.h"
#include "security/schnorr.h"
#include "transport/transport_utils.h"
#include "dht/dht_key.h"
#include "network/network_utils.h"
#include "bft/bft_utils.h"

namespace lego {

namespace bft {

void BftProto::SetDefaultBroadcastParam(transport::protobuf::BroadcastParam* broad_param) {
    broad_param->set_layer_left(0);
    broad_param->set_layer_right(std::numeric_limits<uint64_t>::max());
    broad_param->set_ign_bloomfilter_hop(kBftBroadcastIgnBloomfilterHop);
    broad_param->set_stop_times(kBftBroadcastStopTimes);
    broad_param->set_hop_limit(kBftHopLimit);
    broad_param->set_hop_to_layer(kBftHopToLayer);
    broad_param->set_neighbor_count(kBftNeighborCount);
}

void BftProto::LeaderCreatePrepare(
        const dht::NodePtr& local_node,
        const std::string& data,
        const BftInterfacePtr& bft_ptr,
        const security::Signature& sign,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    dht::DhtKeyManager dht_key(bft_ptr->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityLow);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(data);
    bft_msg.set_leader(false);
    bft_msg.set_gid(bft_ptr->gid());
    bft_msg.set_rand(bft_ptr->rand_num());
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_node_id(local_node->id);
    bft_msg.set_status(kBftPrepare);
    bft_msg.set_bft_address(bft_ptr->name());
    bft_msg.set_pool_index(bft_ptr->pool_index());
    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("leader prepare:") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            common::Encode::HexEncode(dht_key.StrKey()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}

void BftProto::BackupCreatePrepare(
        const transport::protobuf::Header& from_header,
        const bft::protobuf::BftMessage& from_bft_msg,
        const dht::NodePtr& local_node,
        const std::string& data,
        const security::CommitSecret& secret,
        bool agree,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(from_header.src_dht_key());
    msg.set_des_dht_key_hash(common::Hash::Hash64(from_header.src_dht_key()));
    msg.set_priority(transport::kTransportPriorityLow);
    msg.set_id(from_header.id());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(data);
    bft_msg.set_leader(true);
    bft_msg.set_gid(from_bft_msg.gid());
    bft_msg.set_rand(from_bft_msg.rand());
    bft_msg.set_net_id(from_bft_msg.net_id());
    bft_msg.set_node_id(local_node->id);
    bft_msg.set_agree(agree);
    std::string secret_str;
    secret.Serialize(secret_str);
    bft_msg.set_secret(secret_str);
    security::Signature sign;
    std::string sha128 = common::Hash::Hash128(data);
    bool sign_res = security::Schnorr::Instance()->Sign(
            sha128,
            *(security::Schnorr::Instance()->prikey().get()),
            *(security::Schnorr::Instance()->pubkey().get()),
            sign);
    if (!sign_res) {
        BFT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    bft_msg.set_status(kBftPrepare);
    msg.set_data(bft_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("backup prepare:") +
        local_node->public_ip + "-" +
        std::to_string(local_node->public_port) + ", to " +
        common::Encode::HexEncode(from_header.src_dht_key()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}

void BftProto::LeaderCreatePreCommit(
        const dht::NodePtr& local_node,
        const BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    dht::DhtKeyManager dht_key(bft_ptr->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(bft_ptr->prepare_hash());
    bft_msg.set_leader(false);
    bft_msg.set_gid(bft_ptr->gid());
    bft_msg.set_rand(bft_ptr->rand_num());
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_node_id(local_node->id);
    bft_msg.set_status(kBftPreCommit);
    auto challenge = bft_ptr->challenge();
    std::string challenge_str;
    challenge.Serialize(challenge_str);
    bft_msg.set_challenge(challenge_str);
    security::Signature leader_sign;
    if (!security::Schnorr::Instance()->Sign(
            bft_ptr->prepare_hash(),
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            leader_sign)) {
        BFT_ERROR("leader pre commit signature failed!");
        return;
    }
    std::string sign_challenge_str;
    std::string sign_response_str;
    leader_sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("leader pre commit:") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            common::Encode::HexEncode(dht_key.StrKey()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}

void BftProto::BackupCreatePreCommit(
        const transport::protobuf::Header& from_header,
        const bft::protobuf::BftMessage& from_bft_msg,
        const dht::NodePtr& local_node,
        const std::string& data,
        const security::Response& agg_res,
        bool agree,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(from_header.src_dht_key());
    msg.set_des_dht_key_hash(common::Hash::Hash64(from_header.src_dht_key()));
    msg.set_priority(transport::kTransportPriorityHigh);
    msg.set_id(from_header.id());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(data);
    bft_msg.set_leader(true);
    bft_msg.set_gid(from_bft_msg.gid());
    bft_msg.set_rand(from_bft_msg.rand());
    bft_msg.set_net_id(from_bft_msg.net_id());
    bft_msg.set_node_id(local_node->id);
    bft_msg.set_agree(agree);
    bft_msg.set_status(kBftPreCommit);
    std::string agg_res_str;
    agg_res.Serialize(agg_res_str);
    bft_msg.set_response(agg_res_str);
    security::Signature sign;
    std::string sha128 = common::Hash::Hash128(data);
    bool sign_res = security::Schnorr::Instance()->Sign(
            sha128,
            *(security::Schnorr::Instance()->prikey().get()),
            *(security::Schnorr::Instance()->pubkey().get()),
            sign);
    if (!sign_res) {
        BFT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("backup pre commit:") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            common::Encode::HexEncode(from_header.src_dht_key()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}

void BftProto::LeaderCreateCommit(
        const dht::NodePtr& local_node,
        const BftInterfacePtr& bft_ptr,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    dht::DhtKeyManager dht_key(bft_ptr->network_id(), 0);
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(bft_ptr->prepare_hash());
    bft_msg.set_leader(false);
    bft_msg.set_gid(bft_ptr->gid());
    bft_msg.set_rand(bft_ptr->rand_num());
    bft_msg.set_net_id(bft_ptr->network_id());
    bft_msg.set_node_id(local_node->id);
    bft_msg.set_status(kBftCommit);
    const auto& bitmap_data = bft_ptr->precommit_bitmap().data();
    for (uint32_t i = 0; i < bitmap_data.size(); ++i) {
        bft_msg.add_bitmap(bitmap_data[i]);
    }

    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
            bft_ptr->prepare_hash(),
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            sign);
    if (!sign_res) {
        BFT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    std::string agg_sign_challenge_str;
    std::string agg_sign_response_str;
    bft_ptr->agg_sign()->Serialize(agg_sign_challenge_str, agg_sign_response_str);
    bft_msg.set_agg_sign_challenge(agg_sign_challenge_str);
    bft_msg.set_agg_sign_response(agg_sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("leader commit:") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            common::Encode::HexEncode(dht_key.StrKey()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}

void BftProto::LeaderBroadcastToAccount(
        const dht::NodePtr& local_node,
        uint32_t net_id,
        const std::shared_ptr<bft::protobuf::Block>& block_ptr,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    dht::DhtKeyManager dht_key(net_id, common::RandomCountry());
    msg.set_des_dht_key(dht_key.StrKey());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kBftMessage);
    msg.set_client(false);
    msg.set_hop_count(0);
    auto broad_param = msg.mutable_broadcast();
    SetDefaultBroadcastParam(broad_param);
    bft::protobuf::BftMessage bft_msg;
    bft_msg.set_data(block_ptr->SerializeAsString());
    std::string sha128 = common::Hash::Hash128(bft_msg.data());
    security::Signature sign;
    bool sign_res = security::Schnorr::Instance()->Sign(
            sha128,
            *(security::Schnorr::Instance()->prikey()),
            *(security::Schnorr::Instance()->pubkey()),
            sign);
    if (!sign_res) {
        BFT_ERROR("signature error.");
        return;
    }

    std::string sign_challenge_str;
    std::string sign_response_str;
    sign.Serialize(sign_challenge_str, sign_response_str);
    bft_msg.set_sign_challenge(sign_challenge_str);
    bft_msg.set_sign_response(sign_response_str);
    msg.set_data(bft_msg.SerializeAsString());

#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("LeaderBroadcastToAccount:") +
            local_node->public_ip + "-" +
            std::to_string(local_node->public_port) + ", to " +
            common::Encode::HexEncode(dht_key.StrKey()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin", msg);
#endif
}

}  // namespace bft

}  // namespace lego
