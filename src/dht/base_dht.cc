#include "dht/base_dht.h"

#include <bitset>
#include <algorithm>
#include <functional>
#include <limits>

#include "common/hash.h"
#include "common/encode.h"
#include "common/bloom_filter.h"
#include "transport/multi_thread/processor.h"
#include "transport/transport_utils.h"
#include "broadcast/broadcast_utils.h"
#include "nat_traverse/detection.h"
#include "dht/dht_utils.h"
#include "dht/proto/dht_proto.h"
#include "dht/dht_function.h"
#include "dht/dht_key.h"

namespace lego {

namespace dht {

BaseDht::BaseDht(transport::TransportPtr& transport, NodePtr& local_node)
        : transport_(transport), local_node_(local_node) {
    assert(transport_);
    readonly_dht_ = std::make_shared<Dht>(dht_);
    readonly_hash_sort_dht_ = std::make_shared<Dht>(dht_);
    readony_node_map_ = std::make_shared<std::unordered_map<uint64_t, NodePtr>>(node_map_);
}

BaseDht::~BaseDht() {}

void BaseDht::RegisterDhtMessage() {
    transport::Processor::Instance()->RegisterProcessor(
            common::kDhtMessage,
            std::bind(&BaseDht::HandleMessage, this, std::placeholders::_1));
    nat_detection_->RegisterNatMessage();
}

int BaseDht::Init() {
    nat_detection_ = std::make_shared<nat::Detection>(shared_from_this(), transport_);
    refresh_neighbors_tick_.CutOff(
            kRefreshNeighborPeriod,
            std::bind(&BaseDht::RefreshNeighbors, shared_from_this()));
    heartbeat_tick_.CutOff(
            kHeartbeatPeriod,
            std::bind(&BaseDht::Heartbeat, shared_from_this()));
    uint32_t net_id;
    uint8_t country;
    GetNetIdAndCountry(net_id, country);
    DHT_INFO("dht [%d][%d] init success.", net_id, country);
    return kDhtSuccess;
}

int BaseDht::Destroy() {
    refresh_neighbors_tick_.Destroy();
    heartbeat_tick_.Destroy();
    if (nat_detection_) {
        nat_detection_->Destroy();
    }
    return kDhtSuccess;
}

int BaseDht::Join(NodePtr& node) {
    if (CheckJoin(node) != kDhtSuccess) {
        return kDhtError;
    }

    std::lock_guard<std::mutex> guard(dht_mutex_);
    DhtFunction::PartialSort(local_node_->dht_key, dht_.size(), dht_);
    uint32_t replace_pos = dht_.size() + 1;
    if (!DhtFunction::Displacement(local_node_->dht_key, dht_, node, replace_pos)) {
        DHT_WARN("displacement for new node failed!");
        return kDhtError;
    }

    if (replace_pos < dht_.size()) {
        auto rm_iter = dht_.begin() + replace_pos;
        std::unique_lock<std::mutex> lock_hash(node_map_mutex_);
        auto hash_iter = node_map_.find((*rm_iter)->dht_key_hash);
        if (hash_iter != node_map_.end()) {
            node_map_.erase(hash_iter);
        }
        dht_.erase(rm_iter);
    }

    nat_detection_->Remove(node->dht_key_hash);
    std::unique_lock<std::mutex> lock(node_map_mutex_);
    auto iter = node_map_.insert(std::make_pair(node->dht_key_hash, node));
    if (!iter.second) {
        return kDhtNodeJoined;
    }
    dht_.push_back(node);
    readonly_dht_ = std::make_shared<Dht>(dht_);
    std::sort(
            dht_.begin(),
            dht_.end(),
            [](const NodePtr& lhs, const NodePtr& rhs)->bool {
        return lhs->id_hash < rhs->id_hash;
    });
    readonly_hash_sort_dht_ = std::make_shared<Dht>(dht_);
    readony_node_map_ = std::make_shared<std::unordered_map<uint64_t, NodePtr>>(node_map_);
    return kDhtSuccess;
}

int BaseDht::Drop(NodePtr& node) {
    {
        std::lock_guard<std::mutex> guard(dht_mutex_);
        auto& id_hash = node->id_hash;
        auto iter = std::find_if(
                dht_.begin(),
                dht_.end(),
                [id_hash](const NodePtr& rhs) -> bool {
            return id_hash == rhs->id_hash;
        });

        if (iter != dht_.end()) {
            dht_.erase(iter);
        }
        readonly_dht_ = std::make_shared<Dht>(dht_);
        std::sort(
                dht_.begin(),
                dht_.end(),
                [](const NodePtr& lhs, const NodePtr& rhs)->bool {
            return lhs->id_hash < rhs->id_hash;
        });
        readonly_hash_sort_dht_ = std::make_shared<Dht>(dht_);
    }

    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        auto iter = node_map_.find(node->dht_key_hash);
        if (iter != node_map_.end()) {
            node_map_.erase(iter);
        }
        readony_node_map_ = std::make_shared<std::unordered_map<uint64_t, NodePtr>>(node_map_);
    }
    return kDhtSuccess;
}

void BaseDht::SetFrequently(transport::protobuf::Header& message) {
    message.set_hop_count(0);
    message.set_src_node_id(local_node_->id);
    message.set_src_dht_key(local_node_->dht_key);
    message.set_priority(transport::kTransportPriorityLow);
    message.set_id(common::GlobalInfo::Instance()->MessageId());
    if (message.has_broadcast()) {
        auto broad_param = message.mutable_broadcast();
        broad_param->set_neighbor_count(broadcast::kBroadcastDefaultNeighborCount);
        broad_param->set_hop_limit(broadcast::kBroadcastHopLimit);
        broad_param->set_evil_rate(0);
        broad_param->set_hop_to_layer(broadcast::kBroadcastHopToLayer);
        broad_param->set_ign_bloomfilter_hop(broadcast::kBroadcastIgnBloomfilter);
    }
}

int BaseDht::Bootstrap(const std::vector<NodePtr>& boot_nodes) {
    assert(!boot_nodes.empty());
    for (uint32_t i = 0; i < boot_nodes.size(); ++i) {
        transport::protobuf::Header msg;
        SetFrequently(msg);
        DhtProto::CreateBootstrapRequest(local_node_, boot_nodes[i], msg);
        if (transport_->Send(
                boot_nodes[i]->public_ip,
                boot_nodes[i]->public_port,
                0,
                msg) != transport::kTransportSuccess) {
            DHT_ERROR("send bootstrap reqeust with transport failed!");
        }
        DHT_INFO("join[%s][%d][%s][%s] sent request.",
                boot_nodes[i]->public_ip.c_str(),
                boot_nodes[i]->public_port,
                common::Encode::HexEncode(local_node_->dht_key).c_str(),
                common::Encode::HexEncode(boot_nodes[i]->dht_key).c_str());
    }
    std::unique_lock<std::mutex> lock(join_res_mutex_);
    join_res_con_.wait_for(lock, std::chrono::seconds(3), [this]() -> bool { return joined_; });
    if (!joined_) {
        DHT_WARN("join error.");
        return kDhtError;
    }
    return kDhtSuccess;
}

void BaseDht::SendToClosestNode(transport::protobuf::Header& message) {
    assert(!message.des_dht_key().empty());
    assert(message.des_dht_key() != local_node_->dht_key);
    if (readonly_dht_->empty()) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("dht empty", message);
        return;
    }

    NodePtr node = FindNodeDirect(message);
    if (!node) {
        std::set<std::string> exclude;
        Dht tmp_dht = *readonly_dht_;  // change must copy
        node = DhtFunction::GetClosestNode(
                tmp_dht,
                message.des_dht_key(),
                local_node_->dht_key,
                true,
                exclude);
    }

    if (!node) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("closest node is null", message);
        return;
    }
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("send to closest node", message);
    assert(node->dht_key_hash != local_node_->dht_key_hash);
    transport_->Send(node->public_ip, node->public_port, 0, message);
}

NodePtr BaseDht::FindNodeDirect(transport::protobuf::Header& message) {
    uint64_t des_dht_key_hash{ 0 };
    if (message.has_des_dht_key_hash()) {
        des_dht_key_hash = message.des_dht_key_hash();
    } else {
        des_dht_key_hash = common::Hash::Hash64(message.des_dht_key());
        message.set_des_dht_key_hash(des_dht_key_hash);
    }

    auto iter = readony_node_map_->find(des_dht_key_hash);
    if (iter == readony_node_map_->end()) {
        return nullptr;
    }
    return iter->second;
}

void BaseDht::HandleMessage(transport::protobuf::Header& header) {
    if (header.type() == common::kNatMessage) {
        return nat_detection_->HandleMessage(header);
    }

    if (header.type() != common::kDhtMessage) {
        DHT_ERROR("invalid message type[%d]", header.type());
        return;
    }

    protobuf::DhtMessage dht_msg;
    if (!dht_msg.ParseFromString(header.data())) {
        DHT_ERROR("protobuf::DhtMessage ParseFromString failed!");
        return;
    }

    DhtDispatchMessage(header, dht_msg);
}

void BaseDht::DhtDispatchMessage(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("DhtDispatchMessage:", header);
    if (dht_msg.has_bootstrap_req()) {
        ProcessBootstrapRequest(header, dht_msg);
    }

    if (dht_msg.has_bootstrap_res()) {
        ProcessBootstrapResponse(header, dht_msg);
    }

    if (dht_msg.has_refresh_neighbors_req()) {
        ProcessRefreshNeighborsRequest(header, dht_msg);
    }

    if (dht_msg.has_refresh_neighbors_res()) {
        ProcessRefreshNeighborsResponse(header, dht_msg);
    }

    if (dht_msg.has_heartbeat_req()) {
        ProcessHeartbeatRequest(header, dht_msg);
    }

    if (dht_msg.has_heartbeat_res()) {
        ProcessHeartbeatResponse(header, dht_msg);
    }

    if (dht_msg.has_connect_req()) {
        ProcessConnectRequest(header, dht_msg);
    }
}

void BaseDht::ProcessBootstrapRequest(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
//     if (!CheckDestination(header.des_dht_key(), false)) {
//         DHT_WARN("bootstrap request destination error[%s][%s]!",
//                 common::Encode::HexEncode(header.des_dht_key()).c_str(),
//                 common::Encode::HexEncode(local_node_->dht_key).c_str());
//         return;
//     }

    if (!dht_msg.has_bootstrap_req()) {
        DHT_WARN("dht message has no bootstrap request.");
        return;
    }

    transport::protobuf::Header msg;
    SetFrequently(msg);
    DhtProto::CreateBootstrapResponse(local_node_, header, msg);
    transport_->Send(header.from_ip(), header.from_port(), 0, msg);

    if (header.client()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign
    auto pubkey_ptr = std::make_shared<security::PublicKey>(header.pubkey());
    NodePtr node = std::make_shared<Node>(
            dht_msg.bootstrap_req().node_id(),
            header.src_dht_key(),
            dht_msg.bootstrap_req().nat_type(),
            header.client(),
            header.from_ip(),
            header.from_port(),
            dht_msg.bootstrap_req().local_ip(),
            dht_msg.bootstrap_req().local_port(),
            pubkey_ptr);
    Join(node);
}

void BaseDht::ProcessBootstrapResponse(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("bootstrap request destination error[%s][%s]!",
            common::Encode::HexEncode(header.des_dht_key()).c_str(),
            common::Encode::HexEncode(local_node_->dht_key).c_str());
        return;
    }
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("1 end", header);

    if (!dht_msg.has_bootstrap_res()) {
        return;
    }

    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("1 1 end", header);
    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("2 end", header);
    // check sign
    auto pubkey_ptr = std::make_shared<security::PublicKey>(header.pubkey());
    NodePtr node = std::make_shared<Node>(
            dht_msg.bootstrap_res().node_id(),
            header.src_dht_key(),
            dht_msg.bootstrap_res().nat_type(),
            header.client(),
            header.from_ip(),
            static_cast<uint16_t>(header.from_port()),
            dht_msg.bootstrap_res().local_ip(),
            static_cast<uint16_t>(dht_msg.bootstrap_res().local_port()),
            pubkey_ptr);
    Join(node);
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("3 end", header);
    std::lock_guard<std::mutex> guard(join_res_mutex_);
    if (joined_) {
        return;
    }

    joined_ = true;
    local_node_->public_ip = dht_msg.bootstrap_res().public_ip();
    local_node_->public_port = dht_msg.bootstrap_res().public_port();
    join_res_con_.notify_all();
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("4 end", header);
}

void BaseDht::ProcessRefreshNeighborsRequest(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("refresh neighbors request destnation error[%s][%s]",
                common::Encode::HexEncode(header.des_dht_key()).c_str(),
                common::Encode::HexEncode(local_node_->dht_key).c_str());
        return;
    }

    if (!dht_msg.has_refresh_neighbors_req()) {
        DHT_WARN("not refresh neighbor request.");
        return;
    }
    std::vector<uint64_t> bloomfilter_vec;
    for (auto i = 0; i < dht_msg.refresh_neighbors_req().bloomfilter_size(); ++i) {
        bloomfilter_vec.push_back(dht_msg.refresh_neighbors_req().bloomfilter(i));
    }
    std::shared_ptr<common::BloomFilter> bloomfilter{ nullptr };
    if (!bloomfilter_vec.empty()) {
        bloomfilter = std::make_shared<common::BloomFilter>(
                bloomfilter_vec,
                kRefreshNeighborsBloomfilterHashCount);
    }

    Dht tmp_dht;
    if (bloomfilter) {
        DhtPtr tmp_dht_ptr = readonly_dht_;
        for (auto iter = tmp_dht_ptr->begin(); iter != tmp_dht_ptr->end(); ++iter) {
            if (bloomfilter->Contain((*iter)->dht_key_hash)) {
                continue;
            }
            tmp_dht.push_back((*iter));
        }

        if (!bloomfilter->Contain(local_node_->dht_key_hash)) {
            tmp_dht.push_back(local_node_);
        }
    }
    auto close_nodes = DhtFunction::GetClosestNodes(
            tmp_dht,
            dht_msg.refresh_neighbors_req().des_dht_key(),
            dht_msg.refresh_neighbors_req().count() + 1);
    if (close_nodes.empty()) {
        return;
    }
    transport::protobuf::Header res;
    SetFrequently(res);
    DhtProto::CreateRefreshNeighborsResponse(local_node_, header, close_nodes, res);
    transport_->Send(header.from_ip(), header.from_port(), 0, res);
}

void BaseDht::ProcessRefreshNeighborsResponse(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("refresh neighbors request destnation error[%s][%s]",
                common::Encode::HexEncode(header.des_dht_key()).c_str(),
                common::Encode::HexEncode(local_node_->dht_key).c_str());
        return;
    }

    if (!dht_msg.has_refresh_neighbors_res()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign
    auto pubkey_ptr = std::make_shared<security::PublicKey>(header.pubkey());
    const auto& res_nodes = dht_msg.refresh_neighbors_res().nodes();
    for (int32_t i = 0; i < res_nodes.size(); ++i) {
        NodePtr node = std::make_shared<Node>(
                res_nodes[i].id(),
                res_nodes[i].dht_key(),
                res_nodes[i].nat_type(),
                false,
                res_nodes[i].public_ip(),
                res_nodes[i].public_port(),
                res_nodes[i].local_ip(),
                res_nodes[i].local_port(),
                pubkey_ptr);
        if (CheckJoin(node) != kDhtSuccess) {
            continue;
        }
        AddDetectionTarget(node);
        transport::protobuf::Header msg;
        SetFrequently(msg);
        DhtProto::CreateConnectRequest(local_node_, node, false, msg);
        SendToClosestNode(msg);
    }
}

void BaseDht::AddDetectionTarget(NodePtr& node) {
    nat_detection_->AddTarget(node);
}

void BaseDht::ProcessHeartbeatRequest(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("ProcessHeartbeatRequest destnation error[%s][%s]",
            common::Encode::HexEncode(header.des_dht_key()).c_str(),
            common::Encode::HexEncode(local_node_->dht_key).c_str());
        return;
    }

    if (!dht_msg.has_heartbeat_req()) {
        return;
    }

    NodePtr des_node = nullptr;
    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        auto iter = node_map_.find(dht_msg.heartbeat_req().dht_key_hash());
        if (iter != node_map_.end()) {
            iter->second->heartbeat_alive_times = kHeartbeatDefaultAliveTimes;
            iter->second->heartbeat_send_times = 0;
            des_node = iter->second;
        }
    }

    if (!des_node) {
        return;
    }
    transport::protobuf::Header msg;
    SetFrequently(msg);
    DhtProto::CreateHeatbeatResponse(local_node_, header, msg);
    transport_->Send(header.from_ip(), header.from_port(), 0, msg);
}

void BaseDht::ProcessHeartbeatResponse(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("ProcessHeartbeatResponse destnation error[%s][%s]",
            common::Encode::HexEncode(header.des_dht_key()).c_str(),
            common::Encode::HexEncode(local_node_->dht_key).c_str());
        return;
    }

    if (!dht_msg.has_heartbeat_res()) {
        return;
    }

    {
        std::lock_guard<std::mutex> guard(node_map_mutex_);
        auto iter = node_map_.find(dht_msg.heartbeat_res().dht_key_hash());
        if (iter != node_map_.end()) {
            iter->second->heartbeat_alive_times = kHeartbeatDefaultAliveTimes;
            iter->second->heartbeat_send_times = 0;
        }
    }
}

void BaseDht::ProcessConnectRequest(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    if (header.des_dht_key() != local_node_->dht_key) {
        if (dht_msg.connect_req().direct()) {
            LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("stop direct", header);
            return;
        }
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("proc not this", header);
        SendToClosestNode(header);
        return;
    }

    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    if (!dht_msg.has_connect_req()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign
    auto pubkey_ptr = std::make_shared<security::PublicKey>(header.pubkey());
    NodePtr node = std::make_shared<Node>(
            dht_msg.connect_req().id(),
            dht_msg.connect_req().dht_key(),
            dht_msg.connect_req().nat_type(),
            header.client(),
            dht_msg.connect_req().public_ip(),
            static_cast<uint16_t>(dht_msg.connect_req().public_port()),
            dht_msg.connect_req().local_ip(),
            static_cast<uint16_t>(dht_msg.connect_req().local_port()),
            pubkey_ptr);
    if (dht_msg.connect_req().direct()) {
        Join(node);
    } else {
        nat_detection_->AddTarget(node);
    }
}

bool BaseDht::NodeValid(NodePtr& node) {
    if (node->dht_key.size() != kDhtKeySize) {
        DHT_WARN("dht key size must[%u] now[%u]", kDhtKeySize, node->dht_key.size());
        return false;
    }

    if (node->public_ip.empty() || node->public_port <= 0) {
        DHT_WARN("node[%s] public ip or port invalid!",
                common::Encode::HexEncode(node->id).c_str());
        return false;
    }
    return true;
}

bool BaseDht::NodeJoined(NodePtr& node) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    auto iter = node_map_.find(node->dht_key_hash);
    return iter != node_map_.end();
}

int BaseDht::CheckJoin(NodePtr& node) {
    if (node->nat_type == kNatTypeUnknown) {
        DHT_WARN("invalid node nat type.");
        return kDhtInvalidNat;
    }

    if (!NodeValid(node)) {
        DHT_WARN("node invalid.");
        return kDhtError;
    }

    if (node->dht_key_hash == local_node_->dht_key_hash) {
        DHT_WARN("self join[%s][%s][%llu][%llu]",
                common::Encode::HexEncode(node->dht_key).c_str(),
                common::Encode::HexEncode(local_node_->dht_key).c_str(),
                node->dht_key_hash,
                local_node_->dht_key_hash);
        return kDhtError;
    }

    if (NodeJoined(node)) {
        DHT_DEBUG("node has joined[%s][%s][%d][%llu]",
                common::Encode::HexEncode(node->dht_key).c_str(),
                node->public_ip.c_str(),
                node->public_port,
                node->dht_key_hash);
        return kDhtNodeJoined;
    }

    if (DhtFunction::GetDhtBucket(local_node_->dht_key, node) != kDhtSuccess) {
        DHT_WARN("compute node dht bucket index failed!");
        return kDhtError;
    }

    {
        std::unique_lock<std::mutex> lock(dht_mutex_);
        DhtFunction::PartialSort(local_node_->dht_key, dht_.size(), dht_);
        uint32_t replace_pos = dht_.size() + 1;
        if (!DhtFunction::Displacement(local_node_->dht_key, dht_, node, replace_pos)) {
            DHT_WARN("Displacement failed[%s]",
                    common::Encode::HexEncode(node->id).c_str());
            return kDhtError;
        }
    }
    return kDhtSuccess;
}

bool BaseDht::CheckDestination(const std::string& des_dht_key, bool check_closest) {
    if (des_dht_key == local_node_->dht_key) {
        return true;
    }

    if (!check_closest) {
        return false;
    }

    bool closest = false;
    std::unique_lock<std::mutex> lock(dht_mutex_);
    if (DhtFunction::IsClosest(
            des_dht_key,
            local_node_->dht_key,
            dht_,
            closest) != kDhtSuccess) {
        return false;
    }
    return closest;
}

void BaseDht::RefreshNeighbors() {
    Dht tmp_dht = *readonly_dht_;  // change must copy
    if (!tmp_dht.empty()) {
        auto close_nodes = DhtFunction::GetClosestNodes(
                tmp_dht,
                local_node_->dht_key,
                kDhtNearestNodesCount);
        auto rand_idx = std::rand() % close_nodes.size();
        transport::protobuf::Header msg;
        SetFrequently(msg);
        DhtProto::CreateRefreshNeighborsRequest(
                tmp_dht,
                local_node_,
                close_nodes[rand_idx], msg);
        transport_->Send(
                close_nodes[rand_idx]->public_ip,
                close_nodes[rand_idx]->public_port,
                0,
                msg);
    }
    refresh_neighbors_tick_.CutOff(
            kRefreshNeighborPeriod,
            std::bind(&BaseDht::RefreshNeighbors, shared_from_this()));
}

void BaseDht::Heartbeat() {
    DhtPtr tmp_dht_ptr = readonly_dht_;
    for (auto iter = tmp_dht_ptr->begin(); iter != tmp_dht_ptr->end(); ++iter) {
        auto node = (*iter);
        if (node == nullptr) {
            assert(false);
            continue;
        }

        if (node->heartbeat_send_times >= kHeartbeatMaxSendTimes) {
            DHT_INFO("node[%s][%d] heartbeat failed after [%u] times, drop it!",
                    node->public_ip.c_str(),
                    node->public_port,
                    (uint32_t)node->heartbeat_send_times);
            Drop(node);
            continue;
        }

        if (node->heartbeat_alive_times > 0) {
            --(node->heartbeat_alive_times);
            continue;
        }
        transport::protobuf::Header msg;
        SetFrequently(msg);
        DhtProto::CreateHeatbeatRequest(local_node_, *iter, msg);
        ++(node->heartbeat_send_times);
        transport_->Send(node->public_ip, node->public_port, 0, msg);
    }
    uint32_t net_id;
    uint8_t country;
    GetNetIdAndCountry(net_id, country);
    DHT_DEBUG("[net_id: %u][country: %d] nodes_size[%d] [universal:%d]",
            net_id, country, tmp_dht_ptr->size(), IsUniversal());
    heartbeat_tick_.CutOff(
            kHeartbeatPeriod,
            std::bind(&BaseDht::Heartbeat, shared_from_this()));
}

void BaseDht::GetNetIdAndCountry(uint32_t& net_id, uint8_t& country) {
    net_id = DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key);
    country = DhtKeyManager::DhtKeyGetCountry(local_node_->dht_key);
}

}  // namespace dht

}  // namespace lego
