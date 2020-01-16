#include "stdafx.h"
#include "dht/base_dht.h"

#include <bitset>
#include <algorithm>
#include <functional>
#include <limits>

#include "common/hash.h"
#include "common/encode.h"
#include "common/bloom_filter.h"
#include "common/country_code.h"
#include "ip/ip_with_country.h"
#include "transport/processor.h"
#include "transport/transport_utils.h"
#include "transport/multi_thread.h"
#include "broadcast/broadcast_utils.h"
#include "nat_traverse/detection.h"
#include "dht/dht_utils.h"
#include "dht/proto/dht_proto.h"
#include "dht/dht_function.h"
#include "dht/dht_key.h"
#include "init/update_vpn_init.h"
#include "network/network_utils.h"

namespace lego {

namespace dht {

BaseDht::BaseDht(transport::TransportPtr& transport, NodePtr& local_node) : local_node_(local_node) {
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
    nat_detection_ = std::make_shared<nat::Detection>(shared_from_this());
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
    std::unique_lock<std::mutex> lock_hash(node_map_mutex_);
    uint32_t b_dht_size = dht_.size();
    uint32_t b_map_size = node_map_.size();
    DhtFunction::PartialSort(local_node_->dht_key, dht_.size(), dht_);
    uint32_t replace_pos = dht_.size() + 1;
    if (!DhtFunction::Displacement(local_node_->dht_key, dht_, node, replace_pos)) {
        DHT_WARN("displacement for new node failed!");
        assert(false);
        return kDhtError;
    }

    if (replace_pos < dht_.size()) {
        auto rm_iter = dht_.begin() + replace_pos;
        auto hash_iter = node_map_.find((*rm_iter)->dht_key_hash);
        if (hash_iter != node_map_.end()) {
            node_map_.erase(hash_iter);
        }
        dht_.erase(rm_iter);
        assert(false);
    }

    nat_detection_->Remove(node->dht_key_hash);
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
    uint32_t e_dht_size = dht_.size();
    uint32_t e_map_size = node_map_.size();
    assert((b_dht_size + 1) == e_dht_size);
    assert((b_map_size + 1) == e_map_size);
    assert(readonly_hash_sort_dht_->size() == e_map_size);
    assert(readony_node_map_->size() == e_dht_size);
    assert(readonly_dht_->size() == e_dht_size);
    return kDhtSuccess;
}

int BaseDht::Drop(NodePtr& node) {
    std::lock_guard<std::mutex> guard1(node_map_mutex_);
    std::lock_guard<std::mutex> guard2(dht_mutex_);
    {
        if (dht_.size() <= kDhtMinReserveNodes) {
            return kDhtError;
        }

        auto& dht_key_hash = node->dht_key_hash;
        auto iter = std::find_if(
                dht_.begin(),
                dht_.end(),
                [dht_key_hash](const NodePtr& rhs) -> bool {
            return dht_key_hash == rhs->dht_key_hash;
        });
        if (iter != dht_.end()) {
            assert((*iter)->id == node->id);
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
        auto iter = node_map_.find(node->dht_key_hash);
        if (iter != node_map_.end()) {
            assert(iter->second->id == node->id);
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

int BaseDht::Bootstrap(const std::vector<NodePtr>& boot_nodes, int32_t get_init_msg) {
    assert(!boot_nodes.empty());
    for (uint32_t i = 0; i < boot_nodes.size(); ++i) {
        transport::protobuf::Header msg;
        SetFrequently(msg);
        DhtProto::CreateBootstrapRequest(local_node_, boot_nodes[i], get_init_msg, msg);
        if (transport::MultiThreadHandler::Instance()->transport()->Send(
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
    if (message.client_proxy() && message.client_handled()) {
        message.set_des_dht_key(message.client_dht_key());
        transport()->Send(message.from_ip(), message.from_port(), 0, message);
        return;
    }

    if (message.des_dht_key() == local_node_->dht_key) {
        DHT_ERROR("send to local dht key failed!");
        return;
    }

    if (readonly_dht_->empty()) {
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("dht empty", message);
        DHT_ERROR("local dht is emppty!");
        return;
    }

    NodePtr node = nullptr;
    if (local_node_->client_mode) {
        std::set<std::string> exclude;
        Dht tmp_dht = *readonly_dht_;  // change must copy
        node = DhtFunction::GetClosestNode(
                tmp_dht,
                local_node_->dht_key,
                local_node_->dht_key,
                true,
                exclude);
    }
    
    if (node == nullptr) {
        node = FindNodeDirect(message);
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
    }

    if (!node) {
        DHT_ERROR("no node to send!");
        LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("closest node is null", message);
        return;
    }
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("send to closest node", message);
    assert(node->dht_key_hash != local_node_->dht_key_hash);
    if (message.type() == common::kBlockMessage) {
        DHT_ERROR("send contract message to [%s:%d] des[%s], next[%s]",
                node->public_ip.c_str(),
                node->public_port,
                common::Encode::HexEncode(node->dht_key).c_str(),
                common::Encode::HexEncode(message.des_dht_key()).c_str());
        printf("send block message to [%s:%d] des[%s], next[%s]\n",
            node->public_ip.c_str(),
            node->public_port,
            common::Encode::HexEncode(node->dht_key).c_str(),
            common::Encode::HexEncode(message.des_dht_key()).c_str());

    }
    transport::MultiThreadHandler::Instance()->transport()->Send(
            node->public_ip, node->public_port, 0, message);
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
    if (!dht_msg.has_bootstrap_req()) {
        DHT_WARN("dht message has no bootstrap request.");
        return;
    }

    transport::protobuf::Header msg;
    SetFrequently(msg);
    DhtProto::CreateBootstrapResponse(
            dht_msg.bootstrap_req().get_init_msg(),
            local_node_,
            header,
            msg);
    transport::MultiThreadHandler::Instance()->transport()->Send(
            header.from_ip(), header.from_port(), 0, msg);

    if (header.client()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign
    auto src_dht_key = DhtKeyManager(header.src_dht_key());
    auto node_country = ip::IpWithCountry::Instance()->GetCountryUintCode(header.from_ip());
    if (node_country != ip::kInvalidCountryCode) {
        std::cout << "node bootstrap: " << header.from_ip() << ":"
                << common::global_code_to_country_map[node_country] << std::endl;
        src_dht_key.SetCountryId(node_country);
    } else {
        std::cout << "node bootstrap: " << header.from_ip() << ":"
            << " get country by ip failed!" << std::endl;
    }

    auto pubkey_ptr = std::make_shared<security::PublicKey>(header.pubkey());
    NodePtr node = std::make_shared<Node>(
            dht_msg.bootstrap_req().node_id(),
            src_dht_key.StrKey(),
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
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("bootstrap request destination error[%s][%s]!",
            common::Encode::HexEncode(header.des_dht_key()).c_str(),
            common::Encode::HexEncode(local_node_->dht_key).c_str());
        return;
    }

    if (!dht_msg.has_bootstrap_res()) {
        return;
    }

    if (!header.has_pubkey() || header.pubkey().empty()) {
        assert(false);
        return;
    }
    // check sign

    auto pubkey_ptr = std::make_shared<security::PublicKey>(header.pubkey());
    NodePtr node = std::make_shared<Node>(
            dht_msg.bootstrap_res().node_id(),
            header.src_dht_key(),
            dht_msg.bootstrap_res().nat_type(),
            false,
            header.from_ip(),
            static_cast<uint16_t>(header.from_port()),
            dht_msg.bootstrap_res().local_ip(),
            static_cast<uint16_t>(dht_msg.bootstrap_res().local_port()),
            pubkey_ptr);
    std::lock_guard<std::mutex> guard(join_res_mutex_);
    if (dht_msg.bootstrap_res().has_init_message() &&
            !dht_msg.bootstrap_res().init_message().version_info().empty()) {
        init::UpdateVpnInit::Instance()->BootstrapInit(dht_msg.bootstrap_res().init_message());
    }

    if (joined_) {
        Join(node);
        return;
    }

    local_node_->public_ip = dht_msg.bootstrap_res().public_ip();
    local_node_->public_port = dht_msg.bootstrap_res().public_port();
    auto net_id = dht::DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key);
    auto local_dht_key = DhtKeyManager(local_node_->dht_key);
    if (net_id == network::kUniversalNetworkId) {
        auto node_country = ip::IpWithCountry::Instance()->GetCountryUintCode(
                local_node_->public_ip);
        if (node_country != ip::kInvalidCountryCode) {
            local_dht_key.SetCountryId(node_country);
        } else {
            auto server_country_code = dht_msg.bootstrap_res().country_code();
            if (server_country_code != ip::kInvalidCountryCode) {
                node_country = server_country_code;
                local_dht_key.SetCountryId(server_country_code);

                DhtKey::Construct* cons_key = (DhtKey::Construct*)(local_dht_key.StrKey().c_str());

                std::cout << "joined success and get counry from server: "
                    << server_country_code << ":" << common::global_code_to_country_map[node_country]
                    << "country: " << (uint32_t)cons_key->country
                    << ", r1: " << (uint32_t)cons_key->reserve1
                    << ", r2: " << (uint32_t)cons_key->reserve2
                    << ", r3: " << (uint32_t)cons_key->reserve3
                    << std::endl;
            }
        }
        common::GlobalInfo::Instance()->set_country(node_country);
    } else {
        local_dht_key.SetCountryId(common::GlobalInfo::Instance()->country());
    }

    local_node_->dht_key = local_dht_key.StrKey();


    local_node_->dht_key_hash = common::Hash::Hash64(local_node_->dht_key);
    join_res_con_.notify_all();
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("4 end", header);
    if (Join(node) != kDhtSuccess) {
        std::cout << "node joined with bootstrap failed!" << std::endl;
    } else {
        std::cout << "node joined with bootstrap success!" << std::endl;
        joined_ = true;
    }
}

void BaseDht::ProcessRefreshNeighborsRequest(
        transport::protobuf::Header& header,
        protobuf::DhtMessage& dht_msg) {
    LEGO_NETWORK_DEBUG_FOR_PROTOMESSAGE("end", header);
    if (!CheckDestination(header.des_dht_key(), false)) {
        DHT_WARN("refresh neighbors request destnation error[%s][%s]"
                "from[%s][%d]to[%s][%d]",
                common::Encode::HexEncode(header.des_dht_key()).c_str(),
                common::Encode::HexEncode(local_node_->dht_key).c_str(),
                header.from_ip().c_str(),
                header.from_port(),
                local_node_->public_ip.c_str(),
                local_node_->public_port);
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
            kRefreshNeighborsDefaultCount + 1);
    if (close_nodes.empty()) {
        return;
    }
    transport::protobuf::Header res;
    SetFrequently(res);
    DhtProto::CreateRefreshNeighborsResponse(local_node_, header, close_nodes, res);
    transport::MultiThreadHandler::Instance()->transport()->Send(
            header.from_ip(), header.from_port(), 0, res);
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
        transport::MultiThreadHandler::Instance()->transport()->Send(
                node->public_ip, node->public_port, 0, msg);
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

    transport::protobuf::Header msg;
    SetFrequently(msg);
    DhtProto::CreateHeatbeatResponse(local_node_, header, msg);
    transport::MultiThreadHandler::Instance()->transport()->Send(
            header.from_ip(), header.from_port(), 0, msg);
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
    Join(node);
    nat_detection_->AddTarget(node);
}

bool BaseDht::NodeValid(NodePtr& node) {
    if (node->dht_key.size() != kDhtKeySize) {
        DHT_ERROR("dht key size must[%u] now[%u]", kDhtKeySize, node->dht_key.size());
        return false;
    }

    if (node->public_ip.empty() || node->public_port <= 0) {
        DHT_ERROR("node[%s] public ip or port invalid!",
                common::Encode::HexEncode(node->id).c_str());
        return false;
    }

    auto country_id = ip::IpWithCountry::Instance()->GetCountryUintCode(node->public_ip);
    auto dht_key_country_code = DhtKeyManager::DhtKeyGetCountry(node->dht_key);
    if (country_id != ip::kInvalidCountryCode) {
        if (country_id != dht_key_country_code) {
            DHT_ERROR("node public ip[%s] country [%d] not equal to node dht key country[%d]",
                    node->public_ip.c_str(),
                    country_id,
                    dht_key_country_code);
            return false;
        }
    }
    return true;
}

bool BaseDht::NodeJoined(NodePtr& node) {
    std::lock_guard<std::mutex> guard(node_map_mutex_);
    auto iter = node_map_.find(node->dht_key_hash);
    return iter != node_map_.end();
}

int BaseDht::CheckJoin(NodePtr& node) {
    if (node->client_mode) {
        return kDhtError;
    }

    if (node->nat_type == kNatTypeUnknown) {
        DHT_ERROR("invalid node nat type.");
        return kDhtInvalidNat;
    }

    if (!NodeValid(node)) {
        DHT_ERROR("node invalid.");
        return kDhtError;
    }

    if (node->dht_key_hash == local_node_->dht_key_hash) {
        DHT_ERROR("self join[%s][%s][%llu][%llu]",
                common::Encode::HexEncode(node->dht_key).c_str(),
                common::Encode::HexEncode(local_node_->dht_key).c_str(),
                node->dht_key_hash,
                local_node_->dht_key_hash);
        return kDhtError;
    }

    if (NodeJoined(node)) {
        return kDhtNodeJoined;
    }

    if (DhtFunction::GetDhtBucket(local_node_->dht_key, node) != kDhtSuccess) {
        DHT_ERROR("compute node dht bucket index failed!");
        return kDhtError;
    }

    {
        std::unique_lock<std::mutex> lock(dht_mutex_);
        DhtFunction::PartialSort(local_node_->dht_key, dht_.size(), dht_);
        uint32_t replace_pos = dht_.size() + 1;
        if (!DhtFunction::Displacement(local_node_->dht_key, dht_, node, replace_pos)) {
            DHT_ERROR("Displacement failed[%s]",
                    common::Encode::HexEncode(node->id).c_str());
            return kDhtError;
        }
    }
    return kDhtSuccess;
}

bool BaseDht::CheckDestination(const std::string& des_dht_key, bool check_closest) {
    if (local_node_->client_mode) {
        return true;
    }

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
        transport::MultiThreadHandler::Instance()->transport()->Send(
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
        transport::MultiThreadHandler::Instance()->transport()->Send(
                node->public_ip, node->public_port, 0, msg);
    }
    uint32_t net_id;
    uint8_t country;
    GetNetIdAndCountry(net_id, country);
    auto local_net_id = DhtKeyManager::DhtKeyGetNetId(local_node_->dht_key);
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
