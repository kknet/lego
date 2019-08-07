#include "dht/proto/dht_proto.h"

#include "security/schnorr.h"

namespace lego {

namespace dht {

void DhtProto::SetFreqMessage(BaseDhtPtr& dht, transport::protobuf::Header& msg) {
    assert(dht);
    dht->SetFrequently(msg);
}

void DhtProto::CreateBootstrapRequest(
        const NodePtr& local_node,
        const NodePtr& des_node,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(des_node->dht_key);
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kDhtMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    dht::protobuf::DhtMessage dht_msg;
    auto* bootstrap_req = dht_msg.mutable_bootstrap_req();
    bootstrap_req->set_local_ip(local_node->local_ip);
    bootstrap_req->set_local_port(local_node->local_port);
    bootstrap_req->set_node_id(common::GlobalInfo::Instance()->id());
    bootstrap_req->set_nat_type(local_node->nat_type);
    msg.set_data(dht_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("bootstrap req:") + 
        local_node->public_ip + "-" +
        std::to_string(local_node->public_port) + ", to " +
        des_node->public_ip + "-" + std::to_string(des_node->public_port));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin: ", msg);
#endif
}

void DhtProto::CreateBootstrapResponse(
        const NodePtr& local_node,
        const transport::protobuf::Header& header,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(header.id());
    msg.set_type(common::kDhtMessage);
    msg.set_hop_count(0);
    if (header.client()) {
        msg.set_from_ip(header.from_ip());
        msg.set_from_port(header.from_port());
        msg.set_client(header.client());
        msg.set_client_relayed(true);
        msg.set_client_proxy(header.client_proxy());
        msg.set_client_dht_key(header.client_dht_key());
        msg.set_des_dht_key(header.client_dht_key());
    }
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign
    dht::protobuf::DhtMessage res_dht_msg;
    auto* bootstrap_res = res_dht_msg.mutable_bootstrap_res();
    bootstrap_res->set_node_id(common::GlobalInfo::Instance()->id());
    bootstrap_res->set_nat_type(local_node->nat_type);
    bootstrap_res->set_local_ip(local_node->local_ip);
    bootstrap_res->set_local_port(local_node->local_port);
    bootstrap_res->set_public_ip(header.from_ip());
    bootstrap_res->set_public_port(header.from_port());
    msg.set_data(res_dht_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("bootstrap res:") + 
        local_node->public_ip + "-" +
        std::to_string(local_node->public_port) + ", to " +
        header.from_ip() + "-" + std::to_string(header.from_port()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin: ", msg);
#endif
}

void DhtProto::CreateRefreshNeighborsRequest(
        const Dht& dht,
        const NodePtr& local_node,
        const NodePtr& des_node,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(des_node->dht_key);
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kDhtMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    dht::protobuf::DhtMessage dht_msg;
    auto refresh_nei_req = dht_msg.mutable_refresh_neighbors_req();
    refresh_nei_req->set_count(kRefreshNeighborsDefaultCount);
    common::BloomFilter bloomfilter{
            kRefreshNeighborsBloomfilterBitCount,
            kRefreshNeighborsBloomfilterHashCount };
    for (auto iter = dht.begin(); iter != dht.end(); ++iter) {
        bloomfilter.Add((*iter)->dht_key_hash);
    }
    bloomfilter.Add(local_node->dht_key_hash);

    auto& bloomfilter_vec = bloomfilter.data();
    for (uint32_t i = 0; i < bloomfilter_vec.size(); ++i) {
        refresh_nei_req->add_bloomfilter(bloomfilter_vec[i]);
    }
    refresh_nei_req->set_des_dht_key(local_node->dht_key);
    msg.set_data(dht_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    auto debug_info = (std::string("RefreshNeighborsRequest:") +
        local_node->public_ip + std::string("-") +
        std::to_string(local_node->public_port) + std::string(", to ") +
        des_node->public_ip + std::string("-") + std::to_string(des_node->public_port));
    msg.set_debug(debug_info);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin: ", msg);
#endif
}

void DhtProto::CreateRefreshNeighborsResponse(
        const NodePtr& local_node,
        const transport::protobuf::Header& header,
        const std::vector<NodePtr>& nodes,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(header.id());
    msg.set_type(common::kDhtMessage);
    if (header.client()) {
        msg.set_from_ip(header.from_ip());
        msg.set_from_port(header.from_port());
        msg.set_client(header.client());
        msg.set_client_relayed(true);
        msg.set_client_proxy(header.client_proxy());
        msg.set_client_dht_key(header.client_dht_key());
        msg.set_des_dht_key(header.client_dht_key());
    }
    msg.set_hop_count(0);
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    dht::protobuf::DhtMessage dht_msg;
    auto refresh_nei_res = dht_msg.mutable_refresh_neighbors_res();
    auto res_cnt = nodes.size();
    if (res_cnt > kRefreshNeighborsDefaultCount) {
        res_cnt = kRefreshNeighborsDefaultCount;
    }

    for (uint32_t i = 0; i < res_cnt; ++i) {
        auto proto_node = refresh_nei_res->add_nodes();
        proto_node->set_public_ip(nodes[i]->public_ip);
        proto_node->set_public_port(nodes[i]->public_port);
        proto_node->set_local_ip(nodes[i]->local_ip);
        proto_node->set_local_port(nodes[i]->local_port);
        proto_node->set_id(nodes[i]->id);
        proto_node->set_nat_type(nodes[i]->nat_type);
        proto_node->set_dht_key(nodes[i]->dht_key);
    }
    msg.set_data(dht_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("RefreshNeighborsResponse:") +
        local_node->public_ip + "-" +
        std::to_string(local_node->public_port) + ", to " +
        header.from_ip() + "-" + std::to_string(header.from_port()) + "," +
        std::to_string(nodes.size()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin: ", msg);
#endif
}

void DhtProto::CreateHeatbeatRequest(
        const NodePtr& local_node,
        const NodePtr& des_node,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(des_node->dht_key);
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kDhtMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    dht::protobuf::DhtMessage dht_msg;
    auto heartbeat_req = dht_msg.mutable_heartbeat_req();
    heartbeat_req->set_dht_key_hash(local_node->dht_key_hash);
    msg.set_data(dht_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("HeartbeatRequest:") +
        local_node->public_ip + "-" +
        std::to_string(local_node->public_port) + ", to " +
        des_node->public_ip + "-" + std::to_string(des_node->public_port));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin: ", msg);
#endif
}

void DhtProto::CreateHeatbeatResponse(
        const NodePtr& local_node,
        transport::protobuf::Header& header,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(header.src_dht_key());
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(header.id());
    msg.set_type(common::kDhtMessage);
    if (header.client()) {
        msg.set_from_ip(header.from_ip());
        msg.set_from_port(header.from_port());
        msg.set_client(header.client());
        msg.set_client_relayed(true);
        msg.set_client_proxy(header.client_proxy());
        msg.set_client_dht_key(header.client_dht_key());
        msg.set_des_dht_key(header.client_dht_key());
    }
    msg.set_hop_count(0);
    dht::protobuf::DhtMessage dht_msg;
    auto heartbeat_res = dht_msg.mutable_heartbeat_res();
    heartbeat_res->set_dht_key_hash(local_node->dht_key_hash);
    msg.set_data(dht_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("HeartbeatResponse:") +
        local_node->public_ip + "-" +
        std::to_string(local_node->public_port) + ", to " +
        header.from_ip() + "-" + std::to_string(header.from_port()));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin: ", msg);
#endif
}

void DhtProto::CreateConnectRequest(
        const NodePtr& local_node,
        const NodePtr& des_node,
        bool direct,
        transport::protobuf::Header& msg) {
    msg.set_src_dht_key(local_node->dht_key);
    msg.set_des_dht_key(des_node->dht_key);
    msg.set_priority(transport::kTransportPriorityHighest);
    msg.set_id(common::GlobalInfo::Instance()->MessageId());
    msg.set_type(common::kDhtMessage);
    msg.set_client(local_node->client_mode);
    msg.set_hop_count(0);
    msg.set_des_dht_key_hash(des_node->dht_key_hash);
    msg.set_pubkey(security::Schnorr::Instance()->str_pubkey());
    // TODO(tt): add sign

    dht::protobuf::DhtMessage dht_msg;
    auto connect_req = dht_msg.mutable_connect_req();
    connect_req->set_public_ip(local_node->public_ip);
    connect_req->set_public_port(local_node->public_port);
    connect_req->set_local_ip(local_node->local_ip);
    connect_req->set_local_port(local_node->local_port);
    connect_req->set_nat_type(local_node->nat_type);
    connect_req->set_id(local_node->id);
    connect_req->set_dht_key(local_node->dht_key);
    connect_req->set_direct(direct);
    msg.set_data(dht_msg.SerializeAsString());
#ifdef LEGO_TRACE_MESSAGE
    msg.set_debug(std::string("ConnectRequest:") +
        local_node->public_ip + "-" +
        std::to_string(local_node->public_port) + ", to " +
        common::Encode::HexEncode(des_node->dht_key));
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("begin: ", msg);
#endif
}

}  // namespace dht

}  //namespace lego

